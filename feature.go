package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	featureHeaderLen = 3
)

const (
	FeatureUserAuth = 0x01
	FeatureAddr     = 0x02
)

const (
	AddrIPv4   uint8 = 1
	AddrDomain uint8 = 3
	AddrIPv6   uint8 = 4
)

var (
	ErrShortBuffer = errors.New("short buffer")
	ErrBadAddrType = errors.New("bad address type")
)

// Feature represents a feature the client or server owned.
//
// Protocol spec:
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
	Type() uint8
	Encode() ([]byte, error)
	Decode([]byte) error
}

func NewFeature(t uint8, data []byte) (f Feature, err error) {
	switch t {
	case FeatureUserAuth:
		f = new(UserAuthFeature)
	case FeatureAddr:
		f = new(AddrFeature)
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
	return NewFeature(header[0], b)
}

// UserAuthFeature is a relay feature,
// it contains the username and password for user authentication on server side.
//
// Protocol spec:
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

func (f *UserAuthFeature) Type() uint8 {
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

// AddrFeature is a relay feature,
//
// Protocol spec:
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
	AType uint8
	Host  string
	Port  uint16
}

func (f *AddrFeature) Type() uint8 {
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
		buf.WriteByte(f.AType)
		ip4 := net.ParseIP(f.Host).To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		buf.Write(ip4)
	case AddrDomain:
		buf.WriteByte(f.AType)
		if len(f.Host) > 0xFF {
			return nil, errors.New("addr maximum length exceeded")
		}
		buf.WriteByte(uint8(len(f.Host)))
		buf.WriteString(f.Host)
	case AddrIPv6:
		buf.WriteByte(f.AType)
		ip6 := net.ParseIP(f.Host).To16()
		if ip6 == nil {
			ip6 = net.IPv6zero.To16()
		}
		buf.Write(ip6)
	default:
		buf.WriteByte(AddrIPv4)
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

	f.AType = b[0]
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
