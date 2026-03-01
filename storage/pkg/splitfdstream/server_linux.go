//go:build linux

package splitfdstream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"

	fdpass "github.com/cgwalters/jsonrpc-fdpass-go"
	"golang.org/x/sys/unix"
)

// JSON-RPC 2.0 standard error codes as documented here: https://www.jsonrpc.org/specification
const (
	jsonrpcInvalidRequest = -32600
	jsonrpcMethodNotFound = -32601
	jsonrpcInvalidParams  = -32602
	jsonrpcServerError    = -32000
)

// sendRetry retries sender.Send on EAGAIN (non-blocking socket buffer full).
func sendRetry(sender *fdpass.Sender, msg *fdpass.MessageWithFds) error {
	for {
		err := sender.Send(msg)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			runtime.Gosched()
			continue
		}
		return err
	}
}

// JSONRPCServer manages a JSON-RPC server using the external library.
type JSONRPCServer struct {
	driver      SplitFDStreamDriver
	store       Store
	listener    net.Listener
	running     bool
	mu          sync.RWMutex
	shutdown    chan struct{}
	connections sync.WaitGroup
}

// NewJSONRPCServer creates a new JSON-RPC server.
func NewJSONRPCServer(driver SplitFDStreamDriver, store Store) *JSONRPCServer {
	return &JSONRPCServer{
		driver:   driver,
		store:    store,
		shutdown: make(chan struct{}),
	}
}

// Start starts the JSON-RPC server listening on the given Unix socket.
func (s *JSONRPCServer) Start(socketPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", socketPath, err)
	}

	s.listener = listener
	s.running = true

	go s.acceptConnections()

	return nil
}

// Stop stops the JSON-RPC server.
func (s *JSONRPCServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	close(s.shutdown)
	if s.listener != nil {
		s.listener.Close()
	}
	s.connections.Wait()
	s.running = false

	return nil
}

func (s *JSONRPCServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				continue
			}
		}

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}

		s.TrackConnection()
		go s.HandleConnection(unixConn)
	}
}

// TrackConnection increments the connection counter.  Call this before
// spawning a goroutine that calls HandleConnection so that Stop()'s
// Wait() cannot return before the handler has started.
func (s *JSONRPCServer) TrackConnection() {
	s.connections.Add(1)
}

// HandleConnection handles a single client connection.
// The caller must call TrackConnection before spawning HandleConnection
// in a goroutine.
func (s *JSONRPCServer) HandleConnection(conn *net.UnixConn) {
	defer s.connections.Done()
	defer conn.Close()

	receiver := fdpass.NewReceiver(conn)
	sender := fdpass.NewSender(conn)
	defer receiver.Close()

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		msgWithFds, err := receiver.Receive()
		if err != nil {
			return
		}

		req, ok := msgWithFds.Message.(*fdpass.Request)
		if !ok {
			resp := fdpass.NewErrorResponse(
				&fdpass.Error{Code: jsonrpcInvalidRequest, Message: "Invalid Request"},
				nil,
			)
			if err := sendRetry(sender, &fdpass.MessageWithFds{Message: resp}); err != nil {
				return
			}
			continue
		}

		s.handleRequest(sender, req, msgWithFds.FileDescriptors)
	}
}

func (s *JSONRPCServer) handleRequest(sender *fdpass.Sender, req *fdpass.Request, fds []*os.File) {
	switch req.Method {
	case "GetSplitFDStream":
		s.handleGetSplitFDStream(sender, req)
	case "GetImage":
		s.handleGetImage(sender, req)
	default:
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcMethodNotFound, Message: fmt.Sprintf("method %q not found", req.Method)},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
	}
}

func (s *JSONRPCServer) handleGetSplitFDStream(sender *fdpass.Sender, req *fdpass.Request) {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcInvalidParams, Message: "params must be an object"},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	layerID, _ := params["layerId"].(string)
	if layerID == "" {
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcInvalidParams, Message: "layerId is required"},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	parentID, _ := params["parentId"].(string)

	stream, fileFDs, err := s.driver.GetSplitFDStream(layerID, parentID, &GetSplitFDStreamOpts{})
	if err != nil {
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcServerError, Message: err.Error()},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	// Write stream data directly to a memfd to avoid holding the entire
	// stream in memory twice (once in the byte slice, once in the memfd).
	streamFd, err := unix.MemfdCreate("splitfdstream", unix.MFD_CLOEXEC)
	if err != nil {
		stream.Close()
		for _, f := range fileFDs {
			f.Close()
		}
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcServerError, Message: fmt.Sprintf("memfd_create: %v", err)},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}
	streamFile := os.NewFile(uintptr(streamFd), "splitfdstream")
	streamSize, err := io.Copy(streamFile, stream)
	stream.Close()
	if err != nil {
		streamFile.Close()
		for _, f := range fileFDs {
			f.Close()
		}
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcServerError, Message: fmt.Sprintf("failed to write stream to memfd: %v", err)},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}
	if _, err := streamFile.Seek(0, 0); err != nil {
		streamFile.Close()
		for _, f := range fileFDs {
			f.Close()
		}
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcServerError, Message: fmt.Sprintf("memfd seek: %v", err)},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	// Prepend the stream memfd to the file descriptor list.
	// allFDs[0] = stream data, allFDs[1:] = content file descriptors.
	allFDs := make([]*os.File, 0, 1+len(fileFDs))
	allFDs = append(allFDs, streamFile)
	allFDs = append(allFDs, fileFDs...)

	// Send the response with the first batch of FDs.
	// The library limits to MaxFDsPerMessage per sendmsg, so remaining
	// FDs are sent as follow-up "fds" notifications.
	firstBatch := allFDs
	if len(firstBatch) > fdpass.MaxFDsPerMessage {
		firstBatch = allFDs[:fdpass.MaxFDsPerMessage]
	}

	result := map[string]interface{}{
		"streamSize": streamSize,
		"totalFDs":   len(allFDs),
	}

	resp := fdpass.NewResponse(result, req.ID)
	if err := sendRetry(sender, &fdpass.MessageWithFds{
		Message:         resp,
		FileDescriptors: firstBatch,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error sending initial response: %v\n", err)
		return
	}

	// Send remaining FDs in batches via notifications
	for i := fdpass.MaxFDsPerMessage; i < len(allFDs); i += fdpass.MaxFDsPerMessage {
		end := i + fdpass.MaxFDsPerMessage
		if end > len(allFDs) {
			end = len(allFDs)
		}
		batch := allFDs[i:end]

		notif := fdpass.NewNotification("fds", nil)
		if err := sendRetry(sender, &fdpass.MessageWithFds{
			Message:         notif,
			FileDescriptors: batch,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "error sending FD batch at %d/%d: %v\n", i, len(allFDs), err)
			return
		}
	}
}

func (s *JSONRPCServer) handleGetImage(sender *fdpass.Sender, req *fdpass.Request) {
	params, ok := req.Params.(map[string]interface{})
	if !ok {
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcInvalidParams, Message: "params must be an object"},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	imageID, _ := params["imageId"].(string)
	if imageID == "" {
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcInvalidParams, Message: "imageId is required"},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	if s.store == nil {
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcServerError, Message: "store not available for image operations"},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	metadata, err := GetImageMetadata(s.store, imageID)
	if err != nil {
		resp := fdpass.NewErrorResponse(
			&fdpass.Error{Code: jsonrpcServerError, Message: fmt.Sprintf("failed to get image metadata: %v", err)},
			req.ID,
		)
		_ = sendRetry(sender, &fdpass.MessageWithFds{Message: resp})
		return
	}

	result := map[string]interface{}{
		"manifest":     string(metadata.ManifestJSON),
		"config":       string(metadata.ConfigJSON),
		"layerDigests": metadata.LayerDigests,
	}

	resp := fdpass.NewResponse(result, req.ID)
	if err := sendRetry(sender, &fdpass.MessageWithFds{Message: resp}); err != nil {
		fmt.Fprintf(os.Stderr, "error sending image response: %v\n", err)
		return
	}
}

// JSONRPCClient implements a JSON-RPC client.
type JSONRPCClient struct {
	conn     *net.UnixConn
	sender   *fdpass.Sender
	receiver *fdpass.Receiver
	mu       sync.Mutex
	nextID   int64
}

// NewJSONRPCClient connects to a JSON-RPC server on the given Unix socket.
func NewJSONRPCClient(socketPath string) (*JSONRPCClient, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to socket: %w", err)
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("connection is not a unix socket")
	}

	return &JSONRPCClient{
		conn:     unixConn,
		sender:   fdpass.NewSender(unixConn),
		receiver: fdpass.NewReceiver(unixConn),
		nextID:   1,
	}, nil
}

// Close closes the client connection.
func (c *JSONRPCClient) Close() error {
	if c.receiver != nil {
		c.receiver.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetSplitFDStream sends a GetSplitFDStream request and returns the response.
func (c *JSONRPCClient) GetSplitFDStream(layerID, parentID string) ([]byte, []*os.File, error) {
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.mu.Unlock()

	req := fdpass.NewRequest("GetSplitFDStream", map[string]interface{}{
		"layerId":  layerID,
		"parentId": parentID,
	}, id)

	if err := sendRetry(c.sender, &fdpass.MessageWithFds{Message: req}); err != nil {
		return nil, nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Receive the initial response with stream data and first batch of FDs
	respMsg, err := c.receiver.Receive()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to receive response: %w", err)
	}

	resp, ok := respMsg.Message.(*fdpass.Response)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected response type: %T", respMsg.Message)
	}

	if resp.Error != nil {
		return nil, nil, fmt.Errorf("server error: %s", resp.Error.Message)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("unexpected result type: %T", resp.Result)
	}

	// Collect FDs: first batch came with the response
	var allFDs []*os.File
	allFDs = append(allFDs, respMsg.FileDescriptors...)

	// Read totalFDs to know how many more to expect
	totalFDs := 0
	if tf, ok := result["totalFDs"].(float64); ok {
		totalFDs = int(tf)
	}

	// Receive remaining FDs from follow-up notifications
	for len(allFDs) < totalFDs {
		msg, err := c.receiver.Receive()
		if err != nil {
			for _, f := range allFDs {
				f.Close()
			}
			return nil, nil, fmt.Errorf("failed to receive FD batch (%d/%d received): %w", len(allFDs), totalFDs, err)
		}
		allFDs = append(allFDs, msg.FileDescriptors...)
	}

	if len(allFDs) == 0 {
		return nil, nil, fmt.Errorf("no file descriptors received")
	}

	// allFDs[0] is a memfd containing the stream data, the rest are content FDs
	streamFile := allFDs[0]
	contentFDs := allFDs[1:]

	streamData, err := io.ReadAll(streamFile)
	streamFile.Close()
	if err != nil {
		for _, f := range contentFDs {
			f.Close()
		}
		return nil, nil, fmt.Errorf("failed to read stream data from fd: %w", err)
	}

	return streamData, contentFDs, nil
}

// GetImage sends a GetImage request and returns image metadata.
func (c *JSONRPCClient) GetImage(imageID string) (*ImageMetadata, error) {
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.mu.Unlock()

	req := fdpass.NewRequest("GetImage", map[string]interface{}{
		"imageId": imageID,
	}, id)

	if err := sendRetry(c.sender, &fdpass.MessageWithFds{Message: req}); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	respMsg, err := c.receiver.Receive()
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	resp, ok := respMsg.Message.(*fdpass.Response)
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", respMsg.Message)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("server error: %s", resp.Error.Message)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type: %T", resp.Result)
	}

	manifestJSON, _ := result["manifest"].(string)
	configJSON, _ := result["config"].(string)

	layerDigestsInterface, _ := result["layerDigests"].([]interface{})
	layerDigests := make([]string, len(layerDigestsInterface))
	for i, v := range layerDigestsInterface {
		layerDigests[i], _ = v.(string)
	}

	return &ImageMetadata{
		ManifestJSON: []byte(manifestJSON),
		ConfigJSON:   []byte(configJSON),
		LayerDigests: layerDigests,
	}, nil
}

// CreateSocketPair creates a pair of connected UNIX sockets.
func CreateSocketPair() (*net.UnixConn, *net.UnixConn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create socket pair: %w", err)
	}

	clientFile := os.NewFile(uintptr(fds[0]), "client")
	serverFile := os.NewFile(uintptr(fds[1]), "server")

	clientConn, err := net.FileConn(clientFile)
	if err != nil {
		clientFile.Close()
		serverFile.Close()
		return nil, nil, fmt.Errorf("failed to create client connection: %w", err)
	}

	serverConn, err := net.FileConn(serverFile)
	if err != nil {
		clientConn.Close()
		serverFile.Close()
		return nil, nil, fmt.Errorf("failed to create server connection: %w", err)
	}

	clientFile.Close()
	serverFile.Close()

	clientUnix, ok := clientConn.(*net.UnixConn)
	if !ok {
		clientConn.Close()
		serverConn.Close()
		return nil, nil, fmt.Errorf("failed to cast client to UnixConn")
	}

	serverUnix, ok := serverConn.(*net.UnixConn)
	if !ok {
		clientConn.Close()
		serverConn.Close()
		return nil, nil, fmt.Errorf("failed to cast server to UnixConn")
	}

	return clientUnix, serverUnix, nil
}
