package targetaccess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const DefaultMaxFrameBytes = 4 << 20

type Session struct {
	conn       *tls.Conn
	reader     *bufio.Reader
	writerMu   sync.Mutex
	maxFrame   uint32
	Negotiated Negotiated
}

func OpenSession(
	ctx context.Context,
	conn net.Conn,
	role TLSRole,
	files TLSFiles,
	local Hello,
	maxFrameBytes uint32,
) (*Session, error) {
	if conn == nil {
		return nil, errors.New("connection is required")
	}
	cfg, err := files.Config(role)
	if err != nil {
		return nil, err
	}
	var secured *tls.Conn
	switch role {
	case TLSClient:
		secured = tls.Client(conn, cfg)
	case TLSServer:
		secured = tls.Server(conn, cfg)
	default:
		return nil, fmt.Errorf("unsupported TLS role %q", role)
	}
	if err := secured.HandshakeContext(ctx); err != nil {
		_ = secured.Close()
		return nil, fmt.Errorf("mTLS handshake: %w", err)
	}
	if maxFrameBytes == 0 {
		maxFrameBytes = DefaultMaxFrameBytes
	}
	session := &Session{
		conn:     secured,
		reader:   bufio.NewReader(secured),
		maxFrame: maxFrameBytes,
	}
	remote, err := session.exchangeHello(role, local)
	if err != nil {
		_ = secured.Close()
		return nil, err
	}
	negotiated, err := Negotiate(local, remote)
	if err != nil {
		_ = secured.Close()
		return nil, err
	}
	session.Negotiated = negotiated
	return session, nil
}

func (s *Session) exchangeHello(role TLSRole, local Hello) (Hello, error) {
	var remote Hello
	switch role {
	case TLSClient:
		if err := s.writeJSON(local); err != nil {
			return Hello{}, fmt.Errorf("write target-access hello: %w", err)
		}
		if err := s.readJSON(&remote); err != nil {
			return Hello{}, fmt.Errorf("read target-access hello: %w", err)
		}
	case TLSServer:
		if err := s.readJSON(&remote); err != nil {
			return Hello{}, fmt.Errorf("read target-access hello: %w", err)
		}
		if err := s.writeJSON(local); err != nil {
			return Hello{}, fmt.Errorf("write target-access hello: %w", err)
		}
	default:
		return Hello{}, fmt.Errorf("unsupported TLS role %q", role)
	}
	return remote, nil
}

func (s *Session) WriteRequest(request Request) error {
	if request.ContractVersion != s.Negotiated.ContractVersion || request.ProtocolVersion != s.Negotiated.ProtocolVersion {
		return errors.New("request version does not match negotiated target-access session")
	}
	return s.writeJSON(request)
}

func (s *Session) ReadRequest(request *Request) error {
	if request == nil {
		return errors.New("request destination is required")
	}
	if err := s.readJSON(request); err != nil {
		return err
	}
	if request.ContractVersion != s.Negotiated.ContractVersion || request.ProtocolVersion != s.Negotiated.ProtocolVersion {
		return errors.New("request version does not match negotiated target-access session")
	}
	return nil
}

func (s *Session) WriteResponse(response Response) error {
	if response.ContractVersion != s.Negotiated.ContractVersion || response.ProtocolVersion != s.Negotiated.ProtocolVersion {
		return errors.New("response version does not match negotiated target-access session")
	}
	return s.writeJSON(response)
}

func (s *Session) ReadResponse(response *Response) error {
	if response == nil {
		return errors.New("response destination is required")
	}
	if err := s.readJSON(response); err != nil {
		return err
	}
	if response.ContractVersion != s.Negotiated.ContractVersion || response.ProtocolVersion != s.Negotiated.ProtocolVersion {
		return errors.New("response version does not match negotiated target-access session")
	}
	return nil
}

func (s *Session) WriteStreamOpen(open StreamOpen) error {
	if err := open.Validate(); err != nil {
		return err
	}
	return s.writeJSON(open)
}

func (s *Session) ReadStreamOpen(open *StreamOpen) error {
	if open == nil {
		return errors.New("stream-open destination is required")
	}
	if err := s.readJSON(open); err != nil {
		return err
	}
	return open.Validate()
}

func (s *Session) WriteStreamEvent(event StreamEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	return s.writeJSON(event)
}

func (s *Session) ReadStreamEvent(event *StreamEvent) error {
	if event == nil {
		return errors.New("stream-event destination is required")
	}
	if err := s.readJSON(event); err != nil {
		return err
	}
	return event.Validate()
}

func (s *Session) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *Session) writeJSON(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > int(s.maxFrame) {
		return fmt.Errorf("target-access frame exceeds %d bytes", s.maxFrame)
	}
	s.writerMu.Lock()
	defer s.writerMu.Unlock()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := s.conn.Write(header[:]); err != nil {
		return err
	}
	_, err = s.conn.Write(data)
	return err
}

func (s *Session) readJSON(target any) error {
	var header [4]byte
	if _, err := io.ReadFull(s.reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > s.maxFrame {
		return fmt.Errorf("invalid target-access frame size %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(s.reader, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}
