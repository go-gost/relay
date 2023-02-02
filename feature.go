package relay

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	featureHeaderLen = 3
)

type FeatureType uint8

const (
	FeatureUserAuth FeatureType = 0x01
	FeatureAddr     FeatureType = 0x02
	FeatureTunnel   FeatureType = 0x03
)

var (
	ErrShortBuffer = errors.New("short buffer")
	ErrBadAddrType = errors.New("bad address type")
)

// Feature represents a feature the client or server owned.
//
// Protocol spec:
//
//	+------+----------+------+
//	| TYPE |  LEN  | FEATURE |
//	+------+-------+---------+
//	|  1   |   2   |   VAR   |
//	+------+-------+---------+
//
//	TYPE - feature type, 1 byte.
//	LEN - length of feature data, 2 bytes.
//	FEATURE - feature data.
type Feature interface {
	Type() FeatureType
	Encode() ([]byte, error)
	Decode([]byte) error
}

func NewFeature(t FeatureType, data []byte) (f Feature, err error) {
	switch t {
	case FeatureUserAuth:
		f = new(UserAuthFeature)
	case FeatureAddr:
		f = new(AddrFeature)
	case FeatureTunnel:
		f = new(TunnelFeature)
	default:
		return nil, errors.New("unknown feature")
	}
	err = f.Decode(data)
	return
}

func ReadFeature(r io.Reader) (Feature, error) {
	var header [featureHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	b := make([]byte, int(binary.BigEndian.Uint16(header[1:3])))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return NewFeature(FeatureType(header[0]), b)
}

// UserAuthFeature is a relay feature,
// it contains the username and password for user authentication on server side.
//
// Protocol spec:
//
//	+------+----------+------+----------+
//	| ULEN |  UNAME   | PLEN |  PASSWD  |
//	+------+----------+------+----------+
//	|  1   | 0 to 255 |  1   | 1 to 255 |
//	+------+----------+------+----------+
//
//	ULEN - length of username field, 1 byte.
//	UNAME - username, variable length, 0 to 255 bytes, 0 means no username.
//	PLEN - length of password field, 1 byte.
//	PASSWD - password, variable length, 0 to 255 bytes, 0 means no password.
type UserAuthFeature struct {
	Username string
	Password string
}

func (f *UserAuthFeature) Type() FeatureType {
	return FeatureUserAuth
}

func (f *UserAuthFeature) Encode() ([]byte, error) {
	var buf bytes.Buffer

	ulen := len(f.Username)
	if ulen > 0xFF {
		return nil, errors.New("username maximum length exceeded")
	}
	buf.WriteByte(uint8(ulen))
	buf.WriteString(f.Username)

	plen := len(f.Password)
	if plen > 0xFF {
		return nil, errors.New("password maximum length exceeded")
	}
	buf.WriteByte(uint8(plen))
	buf.WriteString(f.Password)

	return buf.Bytes(), nil
}

func (f *UserAuthFeature) Decode(b []byte) error {
	if len(b) < 2 {
		return ErrShortBuffer
	}

	pos := 0
	ulen := int(b[pos])

	pos++
	if len(b) < pos+ulen+1 {
		return ErrShortBuffer
	}
	f.Username = string(b[pos : pos+ulen])

	pos += ulen
	plen := int(b[pos])

	pos++
	if len(b) < pos+plen {
		return ErrShortBuffer
	}
	f.Password = string(b[pos : pos+plen])

	return nil
}

type AddrType uint8

const (
	AddrIPv4   AddrType = 1
	AddrDomain AddrType = 3
	AddrIPv6   AddrType = 4
)

// AddrFeature is a relay feature,
//
// Protocol spec:
//
//	+------+----------+----------+
//	| ATYP |   ADDR   |   PORT   |
//	+------+----------+----------+
//	|  1   | Variable |    2     |
//	+------+----------+----------+
//
//	ATYP - address type, 0x01 - IPv4, 0x03 - domain name, 0x04 - IPv6. 1 byte.
//	ADDR - host address, IPv4 (4 bytes), IPV6 (16 bytes) or doman name based on ATYP. For domain name, the first byte is the length of the domain name.
//	PORT - port number, 2 bytes.
type AddrFeature struct {
	AType AddrType
	Host  string
	Port  uint16
}

func (f *AddrFeature) Type() FeatureType {
	return FeatureAddr
}

func (f *AddrFeature) ParseFrom(address string) error {
	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return err
	}

	f.Host = host
	f.Port = uint16(port)
	f.AType = AddrDomain
	if ip := net.ParseIP(f.Host); ip != nil {
		if ip.To4() != nil {
			f.AType = AddrIPv4
		} else {
			f.AType = AddrIPv6
		}
	}

	return nil
}

func (f *AddrFeature) Encode() ([]byte, error) {
	var buf bytes.Buffer

	switch f.AType {
	case AddrIPv4:
		buf.WriteByte(byte(f.AType))
		ip4 := net.ParseIP(f.Host).To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		buf.Write(ip4)
	case AddrDomain:
		buf.WriteByte(byte(f.AType))
		if len(f.Host) > 0xFF {
			return nil, errors.New("addr maximum length exceeded")
		}
		buf.WriteByte(uint8(len(f.Host)))
		buf.WriteString(f.Host)
	case AddrIPv6:
		buf.WriteByte(byte(f.AType))
		ip6 := net.ParseIP(f.Host).To16()
		if ip6 == nil {
			ip6 = net.IPv6zero.To16()
		}
		buf.Write(ip6)
	default:
		buf.WriteByte(byte(AddrIPv4))
		buf.Write(net.IPv4zero.To4())
	}

	var bp [2]byte
	binary.BigEndian.PutUint16(bp[:], f.Port)
	buf.Write(bp[:])

	return buf.Bytes(), nil
}

func (f *AddrFeature) Decode(b []byte) error {
	if len(b) < 4 {
		return ErrShortBuffer
	}

	f.AType = AddrType(b[0])
	pos := 1
	switch f.AType {
	case AddrIPv4:
		if len(b) < 3+net.IPv4len {
			return ErrShortBuffer
		}
		f.Host = net.IP(b[pos : pos+net.IPv4len]).String()
		pos += net.IPv4len
	case AddrIPv6:
		if len(b) < 3+net.IPv6len {
			return ErrShortBuffer
		}
		f.Host = net.IP(b[pos : pos+net.IPv6len]).String()
		pos += net.IPv6len
	case AddrDomain:
		alen := int(b[pos])
		if len(b) < 4+alen {
			return ErrShortBuffer
		}
		pos++
		f.Host = string(b[pos : pos+alen])
		pos += alen
	default:
		return ErrBadAddrType
	}

	f.Port = binary.BigEndian.Uint16(b[pos:])

	return nil
}

type TunnelFlag uint32

const (
	TunnelPrivate TunnelFlag = 0x80000000
)

// TunnelID is an identification for tunnel.
//
//	+------------------+
//	|   ID   |  FLAG   |
//	+------------------+
//	|   16   |    4    |
//	+------------------+
//
//	ID: 16-byte tunnel ID value, should be a valid UUID.
//	FLAG: 4-byte flag, 0x80000000 for private tunnel.
type TunnelID [20]byte

var zeroTunnelID TunnelID

const tunnelIDLen = 16

func NewTunnelID(v []byte) (tid TunnelID) {
	copy(tid[:tunnelIDLen], v[:])
	return
}

func NewPrivateTunnelID(v []byte) (tid TunnelID) {
	copy(tid[:], v[:])
	binary.BigEndian.PutUint32(tid[tunnelIDLen:], uint32(TunnelPrivate))
	return
}

func (tid TunnelID) ID() (id [connectorIDLen]byte) {
	copy(id[:], tid[:tunnelIDLen])
	return
}

func (tid TunnelID) IsZero() bool {
	return bytes.Equal(tid[:tunnelIDLen], zeroTunnelID[:tunnelIDLen])
}

func (tid TunnelID) IsPrivate() bool {
	return binary.BigEndian.Uint32(tid[tunnelIDLen:])&uint32(TunnelPrivate) > 0
}

func (tid TunnelID) Equal(x TunnelID) bool {
	return bytes.Equal(tid[:tunnelIDLen], x[:tunnelIDLen])
}

func (tid TunnelID) String() string {
	var buf [36]byte
	encodeHex(buf[:], tid[:tunnelIDLen])
	return string(buf[:])
}

func encodeHex(dst []byte, v []byte) {
	hex.Encode(dst, v[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], v[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], v[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], v[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], v[10:])
}

type ConnectorFlag uint32

const (
	ConnectorUDP = 0x01
)

// ConnectorID is an identification for tunnel connection.
//
//	+------------------+
//	|   ID   |  FLAG   |
//	+------------------+
//	|   16   |    4    |
//	+------------------+
//
//	ID: 16-byte connector ID value, should be a valid UUID.
//	FLAG: 4-byte flag, 0x1 for UDP connector.
type ConnectorID [20]byte

const connectorIDLen = 16

var zeroConnectorID ConnectorID

func NewConnectorID(v []byte) (cid ConnectorID) {
	copy(cid[:connectorIDLen], v[:])
	return
}

func NewUDPConnectorID(v []byte) (cid ConnectorID) {
	copy(cid[:], v[:])
	binary.BigEndian.PutUint32(cid[connectorIDLen:], uint32(ConnectorUDP))
	return
}

func (cid ConnectorID) ID() (id [connectorIDLen]byte) {
	copy(id[:], cid[:connectorIDLen])
	return
}

func (cid ConnectorID) IsZero() bool {
	return bytes.Equal(cid[:connectorIDLen], zeroConnectorID[:connectorIDLen])
}

func (cid ConnectorID) IsUDP() bool {
	return binary.BigEndian.Uint32(cid[connectorIDLen:])&uint32(ConnectorUDP) > 0
}

func (cid ConnectorID) Equal(x ConnectorID) bool {
	return bytes.Equal(cid[:connectorIDLen], x[:connectorIDLen])
}

func (cid ConnectorID) String() string {
	var buf [36]byte
	encodeHex(buf[:], cid[:connectorIDLen])
	return string(buf[:])
}

// TunnelFeature is a relay feature,
//
// Protocol spec:
//
//	+---------------------+
//	| TUNNEL/CONNECTOR ID |
//	+---------------------+
//	|          16         |
//	+---------------------+
//
//	ID - 16-byte tunnel ID for request or connector ID for response.
type TunnelFeature struct {
	ID [16]byte
}

func (f *TunnelFeature) Type() FeatureType {
	return FeatureTunnel
}

func (f *TunnelFeature) Encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(f.ID[:])
	return buf.Bytes(), nil
}

func (f *TunnelFeature) Decode(b []byte) error {
	if len(b) < tunnelIDLen {
		return ErrShortBuffer
	}
	copy(f.ID[:], b)
	return nil
}
