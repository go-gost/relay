package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	Version1 = 0x01
)

type CmdType uint8

// request commands
const (
	CmdConnect   CmdType = 0x01
	CmdBind      CmdType = 0x02
	CmdAssociate CmdType = 0x03
	CmdMask      CmdType = 0x0F

	// FUDP is a command flag indicating that the request is UDP-oriented.
	// DEPRECATED by network feature.
	FUDP CmdType = 0x80
)

// response status list
const (
	StatusOK                  = 0x00
	StatusBadRequest          = 0x01
	StatusUnauthorized        = 0x02
	StatusForbidden           = 0x03
	StatusTimeout             = 0x04
	StatusServiceUnavailable  = 0x05
	StatusHostUnreachable     = 0x06
	StatusNetworkUnreachable  = 0x07
	StatusInternalServerError = 0x08
)

var (
	ErrBadVersion = errors.New("bad version")
)

var byteOrder = binary.BigEndian

// Request is a relay client request.
//
// Protocol spec:
//
//	+-----+-------------+----+---+-----+----+
//	| VER |  CMD/FLAGS  | FEALEN | FEATURES |
//	+-----+-------------+----+---+-----+----+
//	|  1  |      1      |    2   |    VAR   |
//	+-----+-------------+--------+----------+
//
//	VER - protocol version, 1 byte.
//	CMD/FLAGS - command (low 4-bit) and flags (high 4-bit), 1 byte.
//	FEALEN - length of features, 2 bytes.
//	FEATURES - feature list.
type Request struct {
	Version  uint8
	Cmd      CmdType
	Features []Feature
}

func (req *Request) ReadFrom(r io.Reader) (n int64, err error) {
	var header [4]byte
	nn, err := io.ReadFull(r, header[:])
	n += int64(nn)
	if err != nil {
		return
	}

	if header[0] != Version1 {
		err = ErrBadVersion
		return
	}
	req.Version = header[0]
	req.Cmd = CmdType(header[1])

	flen := int(byteOrder.Uint16(header[2:]))

	if flen == 0 {
		return
	}
	bf := make([]byte, flen)
	nn, err = io.ReadFull(r, bf)
	n += int64(nn)
	if err != nil {
		return
	}
	req.Features, err = readFeatures(bf)
	return
}

func (req *Request) WriteTo(w io.Writer) (n int64, err error) {
	// Collect encoded features and compute total length.
	encoded := make([][]byte, len(req.Features))
	flen := 0
	for i, f := range req.Features {
		b, err := f.Encode()
		if err != nil {
			return 0, err
		}
		encoded[i] = b
		flen += featureHeaderLen + len(b)
	}
	if flen > 0xFFFF {
		return 0, errors.New("features maximum length exceeded")
	}

	buf := make([]byte, 4+flen)
	buf[0] = req.Version
	buf[1] = byte(req.Cmd)
	byteOrder.PutUint16(buf[2:4], uint16(flen))

	pos := 4
	for i, f := range req.Features {
		buf[pos] = byte(f.Type())
		byteOrder.PutUint16(buf[pos+1:pos+3], uint16(len(encoded[i])))
		copy(buf[pos+3:], encoded[i])
		pos += featureHeaderLen + len(encoded[i])
	}

	nn, err := w.Write(buf)
	return int64(nn), err
}

// Response is a relay server response.
//
// Protocol spec:
//
//	+-----+--------+----+---+-----+----+
//	| VER | STATUS | FEALEN | FEATURES |
//	+-----+--------+----+---+-----+----+
//	|  1  |    1   |    2   |    VAR   |
//	+-----+--------+--------+----------+
//
//	VER - protocol version, 1 byte.
//	STATUS - server status, 1 byte.
//	FEALEN - length of features, 2 bytes.
//	FEATURES - feature list.
type Response struct {
	Version  uint8
	Status   uint8
	Features []Feature
}

func (resp *Response) ReadFrom(r io.Reader) (n int64, err error) {
	var header [4]byte
	nn, err := io.ReadFull(r, header[:])
	n += int64(nn)
	if err != nil {
		return
	}

	if header[0] != Version1 {
		err = ErrBadVersion
		return
	}
	resp.Version = header[0]
	resp.Status = header[1]

	flen := int(byteOrder.Uint16(header[2:]))

	if flen == 0 {
		return
	}
	bf := make([]byte, flen)
	nn, err = io.ReadFull(r, bf)
	n += int64(nn)
	if err != nil {
		return
	}

	resp.Features, err = readFeatures(bf)
	return
}

func (resp *Response) WriteTo(w io.Writer) (n int64, err error) {
	// Collect encoded features and compute total length.
	encoded := make([][]byte, len(resp.Features))
	flen := 0
	for i, f := range resp.Features {
		b, err := f.Encode()
		if err != nil {
			return 0, err
		}
		encoded[i] = b
		flen += featureHeaderLen + len(b)
	}
	if flen > 0xFFFF {
		return 0, errors.New("features maximum length exceeded")
	}

	buf := make([]byte, 4+flen)
	buf[0] = resp.Version
	buf[1] = resp.Status
	byteOrder.PutUint16(buf[2:4], uint16(flen))

	pos := 4
	for i, f := range resp.Features {
		buf[pos] = byte(f.Type())
		byteOrder.PutUint16(buf[pos+1:pos+3], uint16(len(encoded[i])))
		copy(buf[pos+3:], encoded[i])
		pos += featureHeaderLen + len(encoded[i])
	}

	nn, err := w.Write(buf)
	return int64(nn), err
}

func readFeatures(b []byte) (fs []Feature, err error) {
	if len(b) == 0 {
		return
	}
	br := bytes.NewReader(b)
	for br.Len() > 0 {
		var f Feature
		f, err = ReadFeature(br)
		if err != nil {
			return
		}
		fs = append(fs, f)
	}
	return
}
