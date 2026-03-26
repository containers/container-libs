package fdpass

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	// MaxFDsPerMessage is the maximum number of file descriptors per message.
	MaxFDsPerMessage = 8
	// ReadBufferSize is the size of the read buffer.
	ReadBufferSize = 4096
)

var (
	// ErrConnectionClosed is returned when the connection is closed.
	ErrConnectionClosed = errors.New("connection closed")
	// ErrFramingError is returned when JSON parsing fails.
	ErrFramingError = errors.New("framing error: invalid JSON")
	// ErrMismatchedCount is returned when the number of FDs doesn't match the fds field.
	ErrMismatchedCount = errors.New("mismatched file descriptor count")
)

// Sender sends JSON-RPC messages with file descriptors over a Unix socket.
type Sender struct {
	conn *net.UnixConn
	mu   sync.Mutex
}

// NewSender creates a new Sender for the given Unix connection.
func NewSender(conn *net.UnixConn) *Sender {
	return &Sender{conn: conn}
}

// Send sends a message with optional file descriptors.
func (s *Sender) Send(msg *MessageWithFds) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Set the fds field on the message based on the number of file descriptors
	fdCount := len(msg.FileDescriptors)
	switch m := msg.Message.(type) {
	case *Request:
		m.SetFDs(fdCount)
	case *Response:
		m.SetFDs(fdCount)
	case *Notification:
		m.SetFDs(fdCount)
	}

	// Serialize the message with the fds field set
	msgData, err := json.Marshal(msg.Message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Get the raw file descriptor for the socket
	rawConn, err := s.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var sendErr error
	err = rawConn.Control(func(fd uintptr) {
		sendErr = s.sendWithFDs(int(fd), msgData, msg.FileDescriptors)
	})
	if err != nil {
		return err
	}
	return sendErr
}

func (s *Sender) sendWithFDs(sockfd int, data []byte, files []*os.File) error {
	bytesSent := 0
	fdsSent := false

	for bytesSent < len(data) {
		remaining := data[bytesSent:]

		var n int
		var err error

		if !fdsSent && len(files) > 0 {
			// First chunk with FDs: use sendmsg with ancillary data
			fds := make([]int, len(files))
			for i, f := range files {
				fds[i] = int(f.Fd())
			}

			rights := unix.UnixRights(fds...)
			n, err = unix.SendmsgN(sockfd, remaining, rights, nil, 0)
			if err != nil {
				return fmt.Errorf("sendmsg failed: %w", err)
			}
			fdsSent = true
		} else {
			// No FDs or FDs already sent: use regular send
			n, err = unix.Write(sockfd, remaining)
			if err != nil {
				return fmt.Errorf("write failed: %w", err)
			}
		}

		bytesSent += n
	}

	return nil
}

// Receiver receives JSON-RPC messages with file descriptors from a Unix socket.
type Receiver struct {
	conn    *net.UnixConn
	buffer  []byte
	fdQueue []*os.File
	mu      sync.Mutex
}

// NewReceiver creates a new Receiver for the given Unix connection.
func NewReceiver(conn *net.UnixConn) *Receiver {
	return &Receiver{
		conn:    conn,
		buffer:  make([]byte, 0),
		fdQueue: make([]*os.File, 0),
	}
}

// Receive receives the next message with its file descriptors.
func (r *Receiver) Receive() (*MessageWithFds, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for {
		// Try to parse a complete message from the buffer
		msg, err := r.tryParseMessage()
		if err != nil {
			return nil, err
		}
		if msg != nil {
			return msg, nil
		}

		// Need more data
		if err := r.readMoreData(); err != nil {
			return nil, err
		}
	}
}

func (r *Receiver) tryParseMessage() (*MessageWithFds, error) {
	if len(r.buffer) == 0 {
		return nil, nil
	}

	// Use streaming JSON decoder to find message boundaries
	decoder := json.NewDecoder(bytes.NewReader(r.buffer))
	var value map[string]interface{}

	err := decoder.Decode(&value)
	if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
		// Incomplete JSON - need more data
		return nil, nil
	}
	if err != nil {
		// Actual parse error - framing error
		return nil, fmt.Errorf("%w: %v", ErrFramingError, err)
	}

	// Successfully parsed a complete JSON value
	// Use InputOffset to find consumed bytes (Go 1.21+)
	bytesConsumed := decoder.InputOffset()

	// Extract the consumed bytes for re-parsing
	consumedData := r.buffer[:bytesConsumed]

	// Remove consumed bytes from buffer
	r.buffer = r.buffer[bytesConsumed:]

	// Read the fds count from the message
	fdCount := GetFDCount(value)

	// Check we have enough FDs
	if fdCount > len(r.fdQueue) {
		return nil, fmt.Errorf("%w: expected %d FDs, have %d in queue",
			ErrMismatchedCount, fdCount, len(r.fdQueue))
	}

	// Dequeue FDs
	fds := make([]*os.File, fdCount)
	copy(fds, r.fdQueue[:fdCount])
	r.fdQueue = r.fdQueue[fdCount:]

	// Parse the message into the appropriate type
	msg, err := ParseMessage(consumedData)
	if err != nil {
		return nil, err
	}

	return &MessageWithFds{
		Message:         msg,
		FileDescriptors: fds,
	}, nil
}

func (r *Receiver) readMoreData() error {
	rawConn, err := r.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var readErr error
	var bytesRead int
	var receivedFDs []*os.File

	err = rawConn.Read(func(fd uintptr) bool {
		bytesRead, receivedFDs, readErr = r.recvWithFDs(int(fd))
		// Return true to indicate we're done with this read operation
		// Return false only if we get EAGAIN/EWOULDBLOCK
		if readErr != nil {
			if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EWOULDBLOCK) {
				readErr = nil
				return false // Tell runtime to wait and retry
			}
		}
		return true
	})

	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}

	if bytesRead == 0 && len(receivedFDs) == 0 {
		return ErrConnectionClosed
	}

	// Append received FDs to queue
	r.fdQueue = append(r.fdQueue, receivedFDs...)

	return nil
}

func (r *Receiver) recvWithFDs(sockfd int) (int, []*os.File, error) {
	buf := make([]byte, ReadBufferSize)
	// Allocate space for control message (for up to MaxFDsPerMessage FDs)
	// Each FD is 4 bytes (int32), use CmsgSpace to get properly aligned size
	oob := make([]byte, unix.CmsgSpace(MaxFDsPerMessage*4))

	n, oobn, _, _, err := unix.Recvmsg(sockfd, buf, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return 0, nil, err
	}

	// Append data to buffer
	if n > 0 {
		r.buffer = append(r.buffer, buf[:n]...)
	}

	// Parse control messages for FDs
	var files []*os.File
	if oobn > 0 {
		scms, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return n, nil, fmt.Errorf("failed to parse control message: %w", err)
		}

		for _, scm := range scms {
			fds, err := unix.ParseUnixRights(&scm)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				files = append(files, os.NewFile(uintptr(fd), ""))
			}
		}
	}

	return n, files, nil
}

// Close closes the receiver and any pending file descriptors in the queue.
func (r *Receiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Close any FDs remaining in the queue to prevent leaks
	for _, f := range r.fdQueue {
		f.Close()
	}
	r.fdQueue = nil

	return nil
}
