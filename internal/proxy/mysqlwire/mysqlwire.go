package mysqlwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Capability flags for MySQL / MariaDB client-server handshake protocol
const (
	ClientLongPassword               uint32 = 0x00000001
	ClientFoundRows                   uint32 = 0x00000002
	ClientLongFlag                   uint32 = 0x00000004
	ClientConnectWithDB              uint32 = 0x00000008
	ClientNoSchema                   uint32 = 0x00000010
	ClientCompress                   uint32 = 0x00000020
	ClientODBC                       uint32 = 0x00000040
	ClientLocalFiles                 uint32 = 0x00000080
	ClientIgnoreSpace                uint32 = 0x00000100
	ClientProtocol41                 uint32 = 0x00000200
	ClientInteractive                uint32 = 0x00000400
	ClientSSL                        uint32 = 0x00000800
	ClientIgnoreSigpipe              uint32 = 0x00001000
	ClientTransactions               uint32 = 0x00002000
	ClientReserved                   uint32 = 0x00004000
	ClientSecureConnection           uint32 = 0x00008000
	ClientMultiStatements            uint32 = 0x00010000
	ClientMultiResults               uint32 = 0x00020000
	ClientPSMultiResults             uint32 = 0x00040000
	ClientPluginAuth                 uint32 = 0x00080000
	ClientConnectAttrs               uint32 = 0x00100000
	ClientPluginAuthLenencClientData uint32 = 0x00200000
)

const MaxHandshakePacketSize = 1024 * 1024 // 1 MB safety limit for handshake packets

var (
	ErrPacketTooShort = errors.New("mysqlwire: packet length is too short")
	ErrPacketTooLarge = errors.New("mysqlwire: packet length exceeds safety limit")
	ErrInvalidPacket  = errors.New("mysqlwire: malformed packet")
	ErrProtocol320    = errors.New("mysqlwire: legacy Protocol 3.20 not supported")
)

// ReadPacket reads a single 4-byte header MySQL packet and returns the payload and sequence ID.
func ReadPacket(r io.Reader) ([]byte, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, 0, err
	}

	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	seqID := header[3]

	if payloadLen > MaxHandshakePacketSize {
		return nil, seqID, fmt.Errorf("%w: %d bytes (max %d)", ErrPacketTooLarge, payloadLen, MaxHandshakePacketSize)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, seqID, err
	}

	return payload, seqID, nil
}

// WritePacket encodes and writes a MySQL packet with a 3-byte length and 1-byte sequence ID.
func WritePacket(w io.Writer, payload []byte, seqID byte) error {
	payloadLen := len(payload)
	header := [4]byte{
		byte(payloadLen),
		byte(payloadLen >> 8),
		byte(payloadLen >> 16),
		seqID,
	}

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ForwardPacket reads a packet from src and writes it verbatim to dst, returning the sequence ID.
func ForwardPacket(dst io.Writer, src io.Reader) (byte, error) {
	payload, seqID, err := ReadPacket(src)
	if err != nil {
		return 0, err
	}
	if err := WritePacket(dst, payload, seqID); err != nil {
		return seqID, err
	}
	return seqID, nil
}

// IsSSLRequest checks if a HandshakeResponse packet is an SSL negotiation request (typically 32 bytes with ClientSSL flag set).
func IsSSLRequest(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	flags := binary.LittleEndian.Uint32(payload[0:4])
	return (flags & ClientSSL) != 0
}

// ValidateDatabaseIdentifier ensures the database identifier adheres to MySQL naming rules
// and does not contain dangerous characters like null bytes, control chars, slashes, or semicolons.
func ValidateDatabaseIdentifier(name string) error {
	if name == "" {
		return errors.New("database identifier cannot be empty")
	}
	if len(name) > 64 {
		return errors.New("database identifier exceeds maximum length of 64 characters")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == 0 || c == '/' || c == '\\' || c == ';' || c < 32 || c == 127 {
			return fmt.Errorf("database identifier contains invalid character '%c'", c)
		}
	}
	return nil
}

// RewriteHandshakeResponseDatabase rewrites or injects the target database schema in a MySQL HandshakeResponse41 packet.
func RewriteHandshakeResponseDatabase(payload []byte, targetDB string) ([]byte, error) {
	if err := ValidateDatabaseIdentifier(targetDB); err != nil {
		return nil, fmt.Errorf("invalid target database identifier: %w", err)
	}

	if len(payload) < 32 {
		return nil, ErrPacketTooShort
	}

	flags := binary.LittleEndian.Uint32(payload[0:4])
	if flags&ClientProtocol41 == 0 {
		return nil, ErrProtocol320
	}

	// HandshakeResponse41 header layout:
	// 4 bytes: client capabilities
	// 4 bytes: max packet size
	// 1 byte: character set
	// 23 bytes: reserved (zeros)
	idx := 32

	// Read username (null-terminated string)
	if idx >= len(payload) {
		return nil, ErrInvalidPacket
	}
	userEnd := bytes.IndexByte(payload[idx:], 0)
	if userEnd == -1 {
		return nil, fmt.Errorf("%w: missing null terminator for username", ErrInvalidPacket)
	}
	idx += userEnd + 1

	// Read auth data
	if flags&ClientPluginAuthLenencClientData != 0 {
		if idx >= len(payload) {
			return nil, ErrInvalidPacket
		}
		// Length-encoded integer
		firstByte := payload[idx]
		idx++
		var authLen int
		switch firstByte {
		case 0xfb:
			authLen = 0
		case 0xfc:
			if idx+2 > len(payload) {
				return nil, ErrInvalidPacket
			}
			authLen = int(binary.LittleEndian.Uint16(payload[idx:]))
			idx += 2
		case 0xfd:
			if idx+3 > len(payload) {
				return nil, ErrInvalidPacket
			}
			authLen = int(payload[idx]) | int(payload[idx+1])<<8 | int(payload[idx+2])<<16
			idx += 3
		case 0xfe:
			if idx+8 > len(payload) {
				return nil, ErrInvalidPacket
			}
			rawLen := binary.LittleEndian.Uint64(payload[idx:])
			idx += 8
			if rawLen > uint64(len(payload)-idx) {
				return nil, fmt.Errorf("%w: auth length exceeds remaining payload", ErrInvalidPacket)
			}
			authLen = int(rawLen)
		default:
			authLen = int(firstByte)
		}
		if authLen < 0 || authLen > len(payload)-idx {
			return nil, ErrInvalidPacket
		}
		idx += authLen
	} else if flags&ClientSecureConnection != 0 {
		if idx >= len(payload) {
			return nil, ErrInvalidPacket
		}
		authLen := int(payload[idx])
		idx++
		if authLen > len(payload)-idx {
			return nil, ErrInvalidPacket
		}
		idx += authLen
	} else {
		authEnd := bytes.IndexByte(payload[idx:], 0)
		if authEnd == -1 {
			return nil, fmt.Errorf("%w: missing null terminator for auth response", ErrInvalidPacket)
		}
		idx += authEnd + 1
	}

	if idx > len(payload) {
		return nil, ErrInvalidPacket
	}

	// Database rewriting or injection
	if flags&ClientConnectWithDB != 0 {
		if idx >= len(payload) {
			return nil, ErrInvalidPacket
		}
		dbEnd := bytes.IndexByte(payload[idx:], 0)
		if dbEnd == -1 {
			return nil, fmt.Errorf("%w: missing null terminator for database name", ErrInvalidPacket)
		}
		trailing := payload[idx+dbEnd+1:]

		var buf bytes.Buffer
		buf.Write(payload[:idx])
		buf.WriteString(targetDB)
		buf.WriteByte(0)
		buf.Write(trailing)
		return buf.Bytes(), nil
	}

	// Client did not set ClientConnectWithDB; enable flag and append database
	newFlags := flags | ClientConnectWithDB
	var buf bytes.Buffer
	var flagBytes [4]byte
	binary.LittleEndian.PutUint32(flagBytes[:], newFlags)

	buf.Write(flagBytes[:])
	buf.Write(payload[4:idx])
	buf.WriteString(targetDB)
	buf.WriteByte(0)
	buf.Write(payload[idx:])
	return buf.Bytes(), nil
}

// BuildErrorPacket constructs a MySQL wire protocol ERR packet with full 4-byte header.
// errCode is the MySQL 16-bit numeric error code (e.g. 1049 for ER_BAD_DB_ERROR, 2002 for CR_CONNECTION_ERROR).
// sqlState is the 5-character SQLSTATE code (e.g. "42000" or "HY000").
func BuildErrorPacket(errCode uint16, sqlState, message string, seqID byte) []byte {
	if sqlState == "" || len(sqlState) != 5 {
		sqlState = "HY000"
	}

	var payload bytes.Buffer
	payload.WriteByte(0xFF) // ERR packet indicator
	var codeBytes [2]byte
	binary.LittleEndian.PutUint16(codeBytes[:], errCode)
	payload.Write(codeBytes[:])
	payload.WriteByte('#') // SQLSTATE marker
	payload.WriteString(sqlState)
	payload.WriteString(message)

	pBytes := payload.Bytes()
	pLen := len(pBytes)
	header := [4]byte{
		byte(pLen),
		byte(pLen >> 8),
		byte(pLen >> 16),
		seqID,
	}

	return append(header[:], pBytes...)
}
