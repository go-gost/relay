package relay

import (
	"bytes"
	"io"
	"testing"
)

func TestUserAuthFeature(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{"normal", "user", "pass", false},
		{"empty", "", "", false},
		{"long username", string(make([]byte, 256)), "", true},
		{"long password", "", string(make([]byte, 256)), true},
		{"unicode", "用户名", "密码", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &UserAuthFeature{Username: tt.username, Password: tt.password}
			if f.Type() != FeatureUserAuth {
				t.Errorf("Type: got %d, want %d", f.Type(), FeatureUserAuth)
			}

			b, err := f.Encode()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Encode error: %v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			var decoded UserAuthFeature
			if err := decoded.Decode(b); err != nil {
				t.Fatalf("Decode error: %v", err)
			}
			if decoded.Username != tt.username {
				t.Errorf("Username: got %q, want %q", decoded.Username, tt.username)
			}
			if decoded.Password != tt.password {
				t.Errorf("Password: got %q, want %q", decoded.Password, tt.password)
			}
		})
	}
}

func TestUserAuthFeatureDecodeShortBuffer(t *testing.T) {
	var f UserAuthFeature
	if err := f.Decode([]byte{0x01}); err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer, got %v", err)
	}
}

func TestAddrFeature(t *testing.T) {
	tests := []struct {
		name    string
		atype   AddrType
		host    string
		port    uint16
		wantErr bool
	}{
		{"ipv4", AddrIPv4, "192.168.1.1", 8080, false},
		{"ipv6", AddrIPv6, "::1", 443, false},
		{"domain", AddrDomain, "example.com", 80, false},
		{"zero port", AddrIPv4, "10.0.0.1", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &AddrFeature{AType: tt.atype, Host: tt.host, Port: tt.port}
			if f.Type() != FeatureAddr {
				t.Errorf("Type: got %d, want %d", f.Type(), FeatureAddr)
			}

			b, err := f.Encode()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Encode error: %v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			var decoded AddrFeature
			if err := decoded.Decode(b); err != nil {
				t.Fatalf("Decode error: %v", err)
			}
			if decoded.AType != tt.atype {
				t.Errorf("AType: got %d, want %d", decoded.AType, tt.atype)
			}
			if decoded.Host != tt.host {
				t.Errorf("Host: got %q, want %q", decoded.Host, tt.host)
			}
			if decoded.Port != tt.port {
				t.Errorf("Port: got %d, want %d", decoded.Port, tt.port)
			}
		})
	}
}

func TestAddrFeatureEncodeDefault(t *testing.T) {
	f := &AddrFeature{AType: 0xFF, Host: "example.com", Port: 8080}
	_, err := f.Encode()
	if err != ErrBadAddrType {
		t.Errorf("expected ErrBadAddrType for unknown AType, got %v", err)
	}
}

func TestAddrFeatureParseFrom(t *testing.T) {
	tests := []struct {
		name    string
		address string
		host    string
		port    uint16
		atype   AddrType
		wantErr bool
	}{
		{"ipv4 with port", "1.2.3.4:80", "1.2.3.4", 80, AddrIPv4, false},
		{"ipv6 with port", "[::1]:443", "::1", 443, AddrIPv6, false},
		{"domain with port", "example.com:8080", "example.com", 8080, AddrDomain, false},
		{"no port", "1.2.3.4", "1.2.3.4", 0, AddrIPv4, false},
		{"invalid port", "host:abc", "", 0, AddrDomain, true},
		{"empty", "", "", 0, AddrDomain, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f AddrFeature
			err := f.ParseFrom(tt.address)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseFrom(%q) error: %v, wantErr=%v", tt.address, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if f.Host != tt.host {
				t.Errorf("Host: got %q, want %q", f.Host, tt.host)
			}
			if f.Port != tt.port {
				t.Errorf("Port: got %d, want %d", f.Port, tt.port)
			}
			if f.AType != tt.atype {
				t.Errorf("AType: got %d, want %d", f.AType, tt.atype)
			}
		})
	}
}

func TestAddrFeatureDecodeShortBuffer(t *testing.T) {
	var f AddrFeature
	if err := f.Decode([]byte{0x01, 0x01, 0x02}); err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer, got %v", err)
	}
	if err := f.Decode([]byte{0xFF, 0x00, 0x00, 0x00}); err != ErrBadAddrType {
		t.Errorf("expected ErrBadAddrType, got %v", err)
	}
}

func TestTunnelID(t *testing.T) {
	v := bytes.Repeat([]byte{0xAB}, 16)
	tid := NewTunnelID(v)

	if tid.IsZero() {
		t.Error("expected non-zero")
	}

	id := tid.ID()
	if !bytes.Equal(id[:], v) {
		t.Errorf("ID: got %x, want %x", id, v)
	}

	if tid.IsPrivate() {
		t.Error("should not be private by default")
	}

	priv := tid.SetPrivate(true)
	if !priv.IsPrivate() {
		t.Error("should be private after SetPrivate(true)")
	}
	if tid.IsPrivate() {
		t.Error("original should not be modified (value type)")
	}

	wt := tid.SetWeight(42)
	if wt.Weight() != 42 {
		t.Errorf("Weight: got %d, want 42", wt.Weight())
	}

	other := NewTunnelID(bytes.Repeat([]byte{0xCD}, 16))
	if tid.Equal(other) {
		t.Error("different IDs should not be equal")
	}
	same := NewTunnelID(v)
	if !tid.Equal(same) {
		t.Error("same IDs should be equal")
	}

	s := tid.String()
	if len(s) != 36 {
		t.Errorf("String length: got %d, want 36 (%s)", len(s), s)
	}
}

func TestNewTunnelIDShortSlice(t *testing.T) {
	v := []byte{0x01, 0x02, 0x03}
	tid := NewTunnelID(v)
	id := tid.ID()
	if !bytes.Equal(id[:3], v) {
		t.Errorf("first 3 bytes mismatch")
	}
	for i := 3; i < tunnelIDLen; i++ {
		if id[i] != 0 {
			t.Errorf("byte %d: expected 0, got %x", i, id[i])
		}
	}
}

func TestNewPrivateTunnelID(t *testing.T) {
	v := make([]byte, 20)
	copy(v, bytes.Repeat([]byte{0xAA}, 16))
	v[19] = 5

	tid := NewPrivateTunnelID(v)
	if !tid.IsPrivate() {
		t.Error("should be private")
	}
	if tid.Weight() != 5 {
		t.Errorf("Weight: got %d, want 5", tid.Weight())
	}
}

func TestConnectorID(t *testing.T) {
	v := bytes.Repeat([]byte{0xEF}, 16)
	cid := NewConnectorID(v)

	if cid.IsZero() {
		t.Error("expected non-zero")
	}

	id := cid.ID()
	if !bytes.Equal(id[:], v) {
		t.Errorf("ID: got %x, want %x", id, v)
	}

	if cid.IsUDP() {
		t.Error("should not be UDP by default")
	}

	udp := cid.SetUDP(true)
	if !udp.IsUDP() {
		t.Error("should be UDP after SetUDP(true)")
	}
	if cid.IsUDP() {
		t.Error("original should not be modified (value type)")
	}

	wt := cid.SetWeight(99)
	if wt.Weight() != 99 {
		t.Errorf("Weight: got %d, want 99", wt.Weight())
	}

	other := NewConnectorID(bytes.Repeat([]byte{0x01}, 16))
	if cid.Equal(other) {
		t.Error("different IDs should not be equal")
	}
}

func TestTunnelFeature(t *testing.T) {
	v := make([]byte, 20)
	copy(v, bytes.Repeat([]byte{0xDE}, 16))
	v[16] = 0x80 // private flag
	v[19] = 10   // weight

	f := &TunnelFeature{ID: NewPrivateTunnelID(v)}
	if f.Type() != FeatureTunnel {
		t.Errorf("Type: got %d, want %d", f.Type(), FeatureTunnel)
	}

	b, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if len(b) != 20 {
		t.Errorf("Encode length: got %d, want 20", len(b))
	}

	var decoded TunnelFeature
	if err := decoded.Decode(b); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if decoded.ID != f.ID {
		t.Errorf("ID mismatch: got %x, want %x", decoded.ID, f.ID)
	}
}

func TestTunnelFeatureDecodeShortBuffer(t *testing.T) {
	var f TunnelFeature
	shortBuf := make([]byte, 19)
	if err := f.Decode(shortBuf); err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer for 19-byte buffer, got %v", err)
	}
}

func TestNetworkFeature(t *testing.T) {
	tests := []NetworkID{NetworkTCP, NetworkUDP, NetworkIP, NetworkUnix, NetworkSerial}

	for _, nw := range tests {
		f := &NetworkFeature{Network: nw}
		if f.Type() != FeatureNetwork {
			t.Errorf("Type: got %d, want %d", f.Type(), FeatureNetwork)
		}

		b, err := f.Encode()
		if err != nil {
			t.Fatalf("Encode(%v) error: %v", nw, err)
		}
		if len(b) != 2 {
			t.Errorf("Encode length: got %d, want 2", len(b))
		}

		var decoded NetworkFeature
		if err := decoded.Decode(b); err != nil {
			t.Fatalf("Decode error: %v", err)
		}
		if decoded.Network != nw {
			t.Errorf("Network: got %d, want %d", decoded.Network, nw)
		}
	}
}

func TestNetworkIDString(t *testing.T) {
	if s := NetworkTCP.String(); s != "tcp" {
		t.Errorf("NetworkTCP.String(): got %q, want %q", s, "tcp")
	}
	if s := NetworkUDP.String(); s != "udp" {
		t.Errorf("NetworkUDP.String(): got %q, want %q", s, "udp")
	}
	if s := NetworkID(0xFF).String(); s != "tcp" {
		t.Errorf("unknown NetworkID.String(): got %q, want %q (default)", s, "tcp")
	}
}

func TestNewFeature(t *testing.T) {
	tests := []struct {
		name    string
		ftype   FeatureType
		data    []byte
		wantErr bool
	}{
		{"userauth", FeatureUserAuth, []byte{0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}, false},
		{"addr ipv4", FeatureAddr, []byte{byte(AddrIPv4), 127, 0, 0, 1, 0x1F, 0x90}, false},
		{"tunnel", FeatureTunnel, make([]byte, 20), false},
		{"network", FeatureNetwork, []byte{0x00, 0x01}, false},
		{"unknown", FeatureType(0xFF), nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFeature(tt.ftype, tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewFeature error: %v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if f.Type() != tt.ftype {
				t.Errorf("Type: got %d, want %d", f.Type(), tt.ftype)
			}
		})
	}
}

func TestZeroTunnelID(t *testing.T) {
	var tid TunnelID
	if !tid.IsZero() {
		t.Error("zero TunnelID should be zero")
	}
}

func TestZeroConnectorID(t *testing.T) {
	var cid ConnectorID
	if !cid.IsZero() {
		t.Error("zero ConnectorID should be zero")
	}
}

func TestUserAuthFeatureDecodeUlenPastBuffer(t *testing.T) {
	var f UserAuthFeature
	// ulen=10 but only 3 bytes available after the length byte
	err := f.Decode([]byte{10, 'a', 'b'})
	if err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer for ulen past buffer, got %v", err)
	}
}

func TestUserAuthFeatureDecodePlenPastBuffer(t *testing.T) {
	var f UserAuthFeature
	// ulen=2 (valid), then plen=5 but only 1 byte available after plen
	err := f.Decode([]byte{2, 'a', 'b', 5, 'c'})
	if err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer for plen past buffer, got %v", err)
	}
}

func TestAddrFeatureEncodeIPv4NilFallback(t *testing.T) {
	f := &AddrFeature{AType: AddrIPv4, Host: "not-an-ip", Port: 8080}
	b, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode should fallback to IPv4zero, got error: %v", err)
	}
	if len(b) != 7 {
		t.Errorf("length: got %d, want 7", len(b))
	}
}

func TestAddrFeatureEncodeDomainTooLong(t *testing.T) {
	f := &AddrFeature{AType: AddrDomain, Host: string(make([]byte, 256)), Port: 8080}
	_, err := f.Encode()
	if err == nil {
		t.Error("expected error for domain exceeding 255 bytes")
	}
}

func TestAddrFeatureEncodeIPv6NilFallback(t *testing.T) {
	f := &AddrFeature{AType: AddrIPv6, Host: "not-an-ip", Port: 8080}
	b, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode should fallback to IPv6zero, got error: %v", err)
	}
	if len(b) != 19 {
		t.Errorf("length: got %d, want 19", len(b))
	}
}

func TestAddrFeatureDecodeShortIPv4(t *testing.T) {
	var f AddrFeature
	// Need 1(type)+4(ipv4)+2(port)=7 bytes, provide only 6
	err := f.Decode([]byte{byte(AddrIPv4), 1, 2, 3, 4, 5})
	if err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer for short IPv4, got %v", err)
	}
}

func TestAddrFeatureDecodeShortIPv6(t *testing.T) {
	var f AddrFeature
	// Need 1(type)+16(ipv6)+2(port)=19 bytes, provide 18
	b := make([]byte, 18)
	b[0] = byte(AddrIPv6)
	err := f.Decode(b)
	if err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer for short IPv6, got %v", err)
	}
}

func TestAddrFeatureDecodeShortDomain(t *testing.T) {
	var f AddrFeature
	// alen=5 declared but buffer only 8 bytes (need 1+1+5+2=9)
	b := []byte{byte(AddrDomain), 5, 'a', 'b', 'c', 'd', 'e', 0}
	err := f.Decode(b)
	if err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer for short domain, got %v", err)
	}
}

func TestTunnelIDSetPrivateFalse(t *testing.T) {
	tid := NewPrivateTunnelID(bytes.Repeat([]byte{0xAB}, 20))
	if !tid.IsPrivate() {
		t.Fatal("expected private after NewPrivateTunnelID")
	}
	cleared := tid.SetPrivate(false)
	if cleared.IsPrivate() {
		t.Error("expected non-private after SetPrivate(false)")
	}
	if !tid.IsPrivate() {
		t.Error("original should not be modified (value type)")
	}
}

func TestConnectorIDSetUDPFalse(t *testing.T) {
	cid := NewUDPConnectorID(bytes.Repeat([]byte{0xCD}, 20))
	if !cid.IsUDP() {
		t.Fatal("expected UDP after NewUDPConnectorID")
	}
	cleared := cid.SetUDP(false)
	if cleared.IsUDP() {
		t.Error("expected non-UDP after SetUDP(false)")
	}
	if !cid.IsUDP() {
		t.Error("original should not be modified (value type)")
	}
}

func TestConnectorIDString(t *testing.T) {
	cid := NewConnectorID(bytes.Repeat([]byte{0xAB}, 16))
	s := cid.String()
	if len(s) != 36 {
		t.Errorf("String length: got %d, want 36 (%s)", len(s), s)
	}
}

func TestConnectorIDEqual(t *testing.T) {
	v := bytes.Repeat([]byte{0xEF}, 16)
	cid := NewConnectorID(v)
	same := NewConnectorID(v)
	if !cid.Equal(same) {
		t.Error("same IDs should be equal")
	}
}

func TestNewUDPConnectorID(t *testing.T) {
	v := make([]byte, 20)
	copy(v, bytes.Repeat([]byte{0xAA}, 16))
	v[19] = 7

	cid := NewUDPConnectorID(v)
	if !cid.IsUDP() {
		t.Error("should be UDP")
	}
	if cid.Weight() != 7 {
		t.Errorf("Weight: got %d, want 7", cid.Weight())
	}
}

func TestNetworkFeatureDecodeShortBuffer(t *testing.T) {
	var f NetworkFeature
	err := f.Decode([]byte{0x00})
	if err != ErrShortBuffer {
		t.Errorf("expected ErrShortBuffer for 1-byte buffer, got %v", err)
	}
}

func TestReadFeatureHeaderError(t *testing.T) {
	r := &errReader{err: io.ErrUnexpectedEOF}
	_, err := ReadFeature(r)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF for header read, got %v", err)
	}
}

func TestReadFeatureBodyError(t *testing.T) {
	// Header says 100 bytes of feature data, but reader fails after header
	r := io.MultiReader(
		bytes.NewReader([]byte{byte(FeatureUserAuth), 0, 100}), // header only
		&errReader{err: io.ErrUnexpectedEOF},
	)
	_, err := ReadFeature(r)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected ErrUnexpectedEOF for body read, got %v", err)
	}
}

type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }
