package relay

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func mkFeature(ftype FeatureType, data []byte) []byte {
	buf := []byte{byte(ftype)}
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(data)))
	return append(append(buf, l...), data...)
}

// FuzzAddrFeatureDecode parses the node-to-node AddrFeature wire format
// (ATYP + ADDR + PORT). Bytes arrive from an upstream relay node, which may be
// malicious; a panic is a DoS on the relay. Seeds cover IPv4/domain/IPv6 and
// the short-buffer / bad-type error paths.
func FuzzAddrFeatureDecode(f *testing.F) {
	ipv4 := []byte{byte(AddrIPv4), 1, 2, 3, 4, 0x1F, 0x90}
	domain := []byte{byte(AddrDomain), 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x01, 0xBB}
	ipv6 := make([]byte, 1+16+2)
	ipv6[0] = byte(AddrIPv6)
	binary.BigEndian.PutUint16(ipv6[17:], 8080)

	f.Add(ipv4)
	f.Add(domain)
	f.Add(ipv6)
	f.Add([]byte{})                          // empty
	f.Add([]byte{0x01, 0x01, 0x02})          // < 4 bytes
	f.Add([]byte{0xFF, 0, 0, 0})             // bad addr type
	f.Add([]byte{byte(AddrIPv4), 1, 2, 3, 4, 5}) // missing port
	f.Fuzz(func(t *testing.T, b []byte) {
		f := &AddrFeature{}
		_ = f.Decode(b) // must not panic / read out of bounds
	})
}

// FuzzReadFeature parses a feature frame (3-byte header: TYPE + LEN + body)
// and dispatches to the concrete feature decoder. The unknown-type branch
// returns an OpaqueFeature (forward-compat path); all branches must be panic-free.
func FuzzReadFeature(f *testing.F) {
	tf := make([]byte, 20)
	f.Add(mkFeature(FeatureAddr, []byte{byte(AddrIPv4), 1, 2, 3, 4, 0x1F, 0x90}))
	f.Add(mkFeature(FeatureUserAuth, []byte{3, 'u', 's', 'e', 4, 'p', 'w', 'd'}))
	f.Add(mkFeature(FeatureTunnel, tf))
	f.Add(mkFeature(FeatureNetwork, []byte{0x00, 0x01}))
	f.Add(mkFeature(FeatureType(0x09), []byte{1, 2, 3})) // opaque / unknown
	f.Add([]byte{0x01})                                  // short header
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadFeature(bytes.NewReader(b))
	})
}

// FuzzUserAuthFeatureDecode parses the ULEN/UNAME/PLEN/PASSWD wire format from
// a relay peer (or a hop's auth forwarder). A panic leaks credentials-handling
// state or DoSes the relay. Seeds cover empty credentials, valid creds, and the
// three short-buffer error paths (header too short, name overrun, password overrun).
func FuzzUserAuthFeatureDecode(f *testing.F) {
	f.Add([]byte{})                          // < 2 bytes
	f.Add([]byte{0})                         // len 1 < 2
	f.Add([]byte{0, 0})                      // empty username, empty password
	f.Add([]byte{3, 'u', 's', 'e', 3, 'p', 'w', 'd'}) // valid: use / pwd
	f.Add([]byte{1, 'a', 3, 'x', 'y', 'z'})  // valid: a / xyz
	f.Add([]byte{5, 1, 2, 3, 4})             // ulen 5 but only 4 bytes follow
	f.Add([]byte{3, 'u', 's', 'e', 9, 'p', 'w', 'd'}) // name ok, password length overruns
	f.Fuzz(func(t *testing.T, b []byte) {
		f := &UserAuthFeature{}
		_ = f.Decode(b) // must not panic / read out of bounds
	})
}

// FuzzTunnelFeatureDecode parses the 20-byte tunnel/connector ID. Bytes arrive
// from an upstream node; the only error path is a short buffer, and only the
// first 20 bytes are consumed (longer input is truncated, not over-read).
func FuzzTunnelFeatureDecode(f *testing.F) {
	f.Add([]byte{})                 // empty
	f.Add(make([]byte, 19))         // 1 byte short of the 20-byte ID
	f.Add(make([]byte, 20))         // exactly the ID length
	f.Add(make([]byte, 21))         // over-long, truncated to 20
	f.Add(make([]byte, 100))        // far over-long
	f.Fuzz(func(t *testing.T, b []byte) {
		f := &TunnelFeature{}
		_ = f.Decode(b) // must not panic / read out of bounds
	})
}

// FuzzNetworkFeatureDecode parses the 2-byte network ID. The only error path is
// a short buffer; unknown IDs are stored as-is (String() maps them to "tcp").
func FuzzNetworkFeatureDecode(f *testing.F) {
	f.Add([]byte{})             // empty
	f.Add([]byte{0})            // 1 byte < 2
	f.Add([]byte{0x00, 0x00})   // TCP
	f.Add([]byte{0x00, 0x01})   // UDP
	f.Add([]byte{0x00, 0x02})   // IP
	f.Add([]byte{0x00, 0x11})   // Serial
	f.Fuzz(func(t *testing.T, b []byte) {
		f := &NetworkFeature{}
		_ = f.Decode(b) // must not panic / read out of bounds
	})
}

// FuzzMetadataFeatureDecode parses the key-value metadata wire format (NKEYS +
// repeated KEYLEN/KEY/VALLEN/VAL). A panic from a crafted byte stream is a DoS
// on the relay. Seeds cover empty list, single/multiple pairs, short buffer, and
// truncated key/value lengths.
func FuzzMetadataFeatureDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 0})                                   // empty
	f.Add([]byte{0, 1, 0, 1, 'k', 0, 1, 'v'})            // single pair
	f.Add([]byte{0, 2, 0, 1, 'a', 0, 1, '1', 0, 1, 'b', 0, 1, '2'}) // two pairs
	f.Add([]byte{0, 3, 0, 5, 'h', 'e', 'l', 'l', 'o'})   // truncated
	f.Fuzz(func(t *testing.T, b []byte) {
		f := &MetadataFeature{}
		_ = f.Decode(b) // must not panic / read out of bounds
	})
}

// FuzzOpaqueFeatureDecode exercises the forward-compat path for unknown feature
// types: it must store the raw bytes verbatim (no panic, no interpretation) so
// the frame round-trips. The fuzzer must not find a panic, and after Decode the
// Encode must return the exact same bytes (the passthrough guarantee).
func FuzzOpaqueFeatureDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4})
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF})
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, b []byte) {
		f := &OpaqueFeature{ftype: FeatureType(0x09)}
		if err := f.Decode(b); err != nil {
			t.Fatalf("OpaqueFeature.Decode returned error: %v", err)
		}
		out, err := f.Encode()
		if err != nil {
			t.Fatalf("OpaqueFeature.Encode returned error: %v", err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("OpaqueFeature round-trip mismatch: got %x, want %x", out, b)
		}
	})
}
