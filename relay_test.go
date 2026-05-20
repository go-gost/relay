package relay

import (
	"bytes"
	"io"
	"testing"
)

func TestRequestReadFromWriteTo(t *testing.T) {
	tests := []struct {
		name string
		req  Request
	}{
		{
			name: "connect with no features",
			req:  Request{Version: Version1, Cmd: CmdConnect},
		},
		{
			name: "bind with user auth",
			req: Request{
				Version: Version1,
				Cmd:     CmdBind,
				Features: []Feature{
					&UserAuthFeature{Username: "user", Password: "pass"},
				},
			},
		},
		{
			name: "associate with multiple features",
			req: Request{
				Version: Version1,
				Cmd:     CmdAssociate,
				Features: []Feature{
					&UserAuthFeature{Username: "admin", Password: "secret"},
					&AddrFeature{AType: AddrIPv4, Host: "127.0.0.1", Port: 8080},
					&TunnelFeature{ID: NewTunnelID(bytes.Repeat([]byte{0xAB}, 16))},
					&NetworkFeature{Network: NetworkTCP},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			nw, err := tt.req.WriteTo(&buf)
			if err != nil {
				t.Fatalf("WriteTo error: %v", err)
			}
			if nw <= 0 {
				t.Errorf("WriteTo returned n=%d", nw)
			}

			var decoded Request
			nr, err := decoded.ReadFrom(&buf)
			if err != nil {
				t.Fatalf("ReadFrom error: %v", err)
			}
			if nr != nw {
				t.Errorf("ReadFrom n=%d, WriteTo n=%d", nr, nw)
			}

			if decoded.Version != tt.req.Version {
				t.Errorf("Version: got %d, want %d", decoded.Version, tt.req.Version)
			}
			if decoded.Cmd != tt.req.Cmd {
				t.Errorf("Cmd: got %d, want %d", decoded.Cmd, tt.req.Cmd)
			}
			if len(decoded.Features) != len(tt.req.Features) {
				t.Fatalf("Features count: got %d, want %d", len(decoded.Features), len(tt.req.Features))
			}
		})
	}
}

func TestRequestReadFromBadVersion(t *testing.T) {
	var req Request
	buf := bytes.NewBuffer([]byte{0x02, byte(CmdConnect), 0, 0})
	_, err := req.ReadFrom(buf)
	if err != ErrBadVersion {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestResponseReadFromWriteTo(t *testing.T) {
	tests := []struct {
		name string
		resp Response
	}{
		{
			name: "ok with no features",
			resp: Response{Version: Version1, Status: StatusOK},
		},
		{
			name: "unauthorized with features",
			resp: Response{
				Version: Version1,
				Status:  StatusUnauthorized,
				Features: []Feature{
					&TunnelFeature{ID: NewConnectorID(bytes.Repeat([]byte{0xCD}, 16))},
					&NetworkFeature{Network: NetworkUDP},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			nw, err := tt.resp.WriteTo(&buf)
			if err != nil {
				t.Fatalf("WriteTo error: %v", err)
			}
			if nw <= 0 {
				t.Errorf("WriteTo returned n=%d", nw)
			}

			var decoded Response
			nr, err := decoded.ReadFrom(&buf)
			if err != nil {
				t.Fatalf("ReadFrom error: %v", err)
			}
			if nr != nw {
				t.Errorf("ReadFrom n=%d, WriteTo n=%d", nr, nw)
			}

			if decoded.Version != tt.resp.Version {
				t.Errorf("Version: got %d, want %d", decoded.Version, tt.resp.Version)
			}
			if decoded.Status != tt.resp.Status {
				t.Errorf("Status: got %d, want %d", decoded.Status, tt.resp.Status)
			}
			if len(decoded.Features) != len(tt.resp.Features) {
				t.Fatalf("Features count: got %d, want %d", len(decoded.Features), len(tt.resp.Features))
			}
		})
	}
}

func TestWriteToMaxFeatureLength(t *testing.T) {
	req := Request{
		Version: Version1,
		Cmd:     CmdConnect,
		Features: []Feature{
			&NetworkFeature{Network: NetworkTCP},
		},
	}
	maxFeatures := (0xFFFF / (featureHeaderLen + networkIDLen)) + 1
	for i := 0; i < maxFeatures; i++ {
		req.Features = append(req.Features, &NetworkFeature{Network: NetworkTCP})
	}

	var buf bytes.Buffer
	n, err := req.WriteTo(&buf)
	if err == nil {
		t.Error("expected error for features exceeding maximum length")
	}
	if n != 0 {
		t.Errorf("expected n=0 on error, got n=%d", n)
	}
}

func TestRequestReadFromHeaderError(t *testing.T) {
	var req Request
	r := &errReader{err: io.ErrUnexpectedEOF}
	_, err := req.ReadFrom(r)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF for header read, got %v", err)
	}
}

func TestRequestReadFromBodyError(t *testing.T) {
	var req Request
	// Valid header with flen=100, but reader fails after header
	r := io.MultiReader(
		bytes.NewReader([]byte{Version1, byte(CmdConnect), 0, 100}),
		&errReader{err: io.ErrUnexpectedEOF},
	)
	_, err := req.ReadFrom(r)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF for body read, got %v", err)
	}
}

func TestRequestWriteToEncodeError(t *testing.T) {
	req := Request{
		Version: Version1,
		Cmd:     CmdConnect,
		Features: []Feature{
			&UserAuthFeature{Username: string(make([]byte, 256))},
		},
	}
	var buf bytes.Buffer
	_, err := req.WriteTo(&buf)
	if err == nil {
		t.Error("expected encode error for username > 255")
	}
}

func TestResponseReadFromHeaderError(t *testing.T) {
	var resp Response
	r := &errReader{err: io.ErrUnexpectedEOF}
	_, err := resp.ReadFrom(r)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF for header read, got %v", err)
	}
}

func TestResponseReadFromBodyError(t *testing.T) {
	var resp Response
	// Valid header with flen=100, but reader fails after header
	r := io.MultiReader(
		bytes.NewReader([]byte{Version1, StatusOK, 0, 100}),
		&errReader{err: io.ErrUnexpectedEOF},
	)
	_, err := resp.ReadFrom(r)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF for body read, got %v", err)
	}
}

func TestResponseReadFromBadVersion(t *testing.T) {
	var resp Response
	buf := bytes.NewBuffer([]byte{0x02, StatusOK, 0, 0})
	_, err := resp.ReadFrom(buf)
	if err != ErrBadVersion {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestResponseWriteToEncodeError(t *testing.T) {
	resp := Response{
		Version: Version1,
		Status:  StatusOK,
		Features: []Feature{
			&UserAuthFeature{Username: string(make([]byte, 256))},
		},
	}
	var buf bytes.Buffer
	_, err := resp.WriteTo(&buf)
	if err == nil {
		t.Error("expected encode error for username > 255")
	}
}

func TestResponseWriteToMaxFeatureLength(t *testing.T) {
	resp := Response{
		Version: Version1,
		Status:  StatusOK,
		Features: []Feature{
			&NetworkFeature{Network: NetworkTCP},
		},
	}
	maxFeatures := (0xFFFF / (featureHeaderLen + networkIDLen)) + 1
	for i := 0; i < maxFeatures; i++ {
		resp.Features = append(resp.Features, &NetworkFeature{Network: NetworkTCP})
	}

	var buf bytes.Buffer
	n, err := resp.WriteTo(&buf)
	if err == nil {
		t.Error("expected error for features exceeding maximum length")
	}
	if n != 0 {
		t.Errorf("expected n=0 on error, got n=%d", n)
	}
}

func TestReadFeaturesEmpty(t *testing.T) {
	fs, err := readFeatures(nil)
	if err != nil {
		t.Errorf("expected no error for empty input, got %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("expected 0 features, got %d", len(fs))
	}
}

func TestRequestReadFromMalformedFeatures(t *testing.T) {
	// Feature header says 10 bytes of data but only 3 bytes follow
	data := []byte{
		Version1, byte(CmdConnect), 0, 6, // header: flen=6
		byte(FeatureUserAuth), 0, 10, // feature header: type=userauth, len=10
		// Only 3 bytes of actual feature data (need 10)
		0x01, 'a', 'b',
	}
	var req Request
	_, err := req.ReadFrom(bytes.NewReader(data))
	if err == nil {
		t.Error("expected error for malformed feature data")
	}
}

