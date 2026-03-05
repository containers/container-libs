//go:build !windows && !darwin

package chrootarchive

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"

	"go.podman.io/storage/pkg/archive"
	"go.podman.io/storage/pkg/fileutils"
	"go.podman.io/storage/pkg/idtools"
	"go.podman.io/storage/pkg/reexec"
	"go.podman.io/storage/pkg/unshare"
)

// fdSocketDescriptor is the file descriptor number for the Unix socket used to
// pass content FDs from the parent to the child process via SCM_RIGHTS.
// FD 3 = tar options, FD 4 = root dir, FD 5 = FD socket.
const fdSocketDescriptor = 5

// UnpackSplitFDStream unpacks a splitfdstream into dest within a chroot for security isolation.
// The stream contains splitfdstream-formatted data read from stdin, and fds are the external
// file descriptors referenced by the stream for reflink-based copying.
//
// Content FDs are sent to the child process via SCM_RIGHTS over a Unix socket
// after the child starts, rather than inherited via ExtraFiles at fork time.
// This avoids exceeding the file descriptor limit during the child's dynamic
// linker phase (EMFILE when loading shared libraries).
func UnpackSplitFDStream(stream io.Reader, fds []*os.File, dest string, options *archive.TarOptions) error {
	if options == nil {
		options = &archive.TarOptions{}
		options.InUserNS = unshare.IsRootless()
	}

	idMappings := idtools.NewIDMappingsFromMaps(options.UIDMaps, options.GIDMaps)
	rootIDs := idMappings.RootPair()

	dest = filepath.Clean(dest)
	if err := fileutils.Exists(dest); os.IsNotExist(err) {
		if err := idtools.MkdirAllAndChownNew(dest, 0o755, rootIDs); err != nil {
			return err
		}
	}

	destVal, err := newUnpackDestination(dest, dest)
	if err != nil {
		return err
	}
	defer destVal.Close()

	// Create pipe for tar options
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("splitfdstream pipe failure: %w", err)
	}

	// Create a Unix socketpair for passing content FDs to the child process.
	socketPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		r.Close()
		w.Close()
		return fmt.Errorf("splitfdstream socketpair failure: %w", err)
	}
	parentSocketFD := socketPair[0]
	childSocket := os.NewFile(uintptr(socketPair[1]), "splitfdstream-child-socket")

	numFDs := strconv.Itoa(len(fds))
	cmd := reexec.Command("storage-untar-splitfdstream", destVal.dest, procPathForFd(rootFileDescriptor), numFDs)
	cmd.Stdin = stream

	cmd.ExtraFiles = append(cmd.ExtraFiles, r)            // fd 3: tar options
	cmd.ExtraFiles = append(cmd.ExtraFiles, destVal.root) // fd 4: root dir
	cmd.ExtraFiles = append(cmd.ExtraFiles, childSocket)  // fd 5: FD socket

	output := bytes.NewBuffer(nil)
	cmd.Stdout = output
	cmd.Stderr = output

	if err := cmd.Start(); err != nil {
		w.Close()
		unix.Close(parentSocketFD)
		childSocket.Close()
		return fmt.Errorf("splitfdstream untar error on re-exec cmd: %w", err)
	}

	// Parent no longer needs the child's socket end or the read end of the pipe
	childSocket.Close()
	r.Close()

	// Send content FDs to the child via SCM_RIGHTS on the Unix socket.
	var sendErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer unix.Close(parentSocketFD)
		for _, fd := range fds {
			rights := unix.UnixRights(int(fd.Fd()))
			if err := unix.Sendmsg(parentSocketFD, []byte{0}, rights, nil, 0); err != nil {
				sendErr = fmt.Errorf("failed to send FD via SCM_RIGHTS: %w", err)
				return
			}
		}
	}()

	if err := json.NewEncoder(w).Encode(options); err != nil {
		w.Close()
		return fmt.Errorf("splitfdstream untar json encode to pipe failed: %w", err)
	}
	w.Close()

	if err := cmd.Wait(); err != nil {
		wg.Wait()
		return fmt.Errorf("splitfdstream unpacking failed (error: %w; output: %s)", err, output)
	}
	wg.Wait()
	if sendErr != nil {
		return sendErr
	}
	return nil
}

// untarSplitFDStream is the reexec handler for "storage-untar-splitfdstream".
// It chroots into the destination and unpacks the splitfdstream from stdin.
func untarSplitFDStream() {
	runtime.LockOSThread()
	flag.Parse()

	var options archive.TarOptions

	// Read the options from the pipe (FD 3)
	if err := json.NewDecoder(os.NewFile(tarOptionsDescriptor, "options")).Decode(&options); err != nil {
		fatal(err)
	}

	dest := flag.Arg(0)
	root := flag.Arg(1)
	numFDs, err := strconv.Atoi(flag.Arg(2))
	if err != nil {
		fatal(fmt.Errorf("invalid numFDs argument %q: %w", flag.Arg(2), err))
	}

	// Handle root directory FD for chroot (same pattern as untar)
	if root == procPathForFd(rootFileDescriptor) {
		rootFd := os.NewFile(rootFileDescriptor, "tar-root")
		defer rootFd.Close()
		if err := unix.Fchdir(int(rootFd.Fd())); err != nil {
			fatal(err)
		}
		root = "."
	} else if root == "" {
		root = dest
	}

	if err := chroot(root); err != nil {
		fatal(err)
	}

	// Raise the file descriptor soft limit to the hard limit to
	// accommodate the content FDs that will be received from the parent.
	if numFDs > 0 {
		var rLimit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rLimit); err == nil {
			rLimit.Cur = rLimit.Max
			_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &rLimit)
		}
	}

	// Receive content FDs from the parent via SCM_RIGHTS on the Unix socket (FD 5).
	fds := make([]*os.File, 0, numFDs)
	if numFDs > 0 {
		buf := make([]byte, 1)
		oob := make([]byte, unix.CmsgSpace(4))
		for i := range numFDs {
			_, oobn, _, _, err := unix.Recvmsg(fdSocketDescriptor, buf, oob, 0)
			if err != nil {
				fatal(fmt.Errorf("receiving content FD %d: %w", i, err))
			}
			scms, err := unix.ParseSocketControlMessage(oob[:oobn])
			if err != nil {
				fatal(fmt.Errorf("parsing socket control message for FD %d: %w", i, err))
			}
			if len(scms) == 0 {
				fatal(fmt.Errorf("no control message received for FD %d", i))
			}
			receivedFDs, err := unix.ParseUnixRights(&scms[0])
			if err != nil {
				fatal(fmt.Errorf("parsing unix rights for FD %d: %w", i, err))
			}
			fds = append(fds, os.NewFile(uintptr(receivedFDs[0]), fmt.Sprintf("content-fd-%d", i)))
		}
	}
	unix.Close(fdSocketDescriptor)

	iter := archive.NewSplitFDStreamIterator(os.Stdin, fds)
	if err := archive.UnpackFromIterator(iter, dest, &options); err != nil {
		fatal(err)
	}
	// fully consume stdin in case it is zero padded
	if _, err := flush(os.Stdin); err != nil {
		fatal(err)
	}

	for _, f := range fds {
		f.Close()
	}

	os.Exit(0)
}
