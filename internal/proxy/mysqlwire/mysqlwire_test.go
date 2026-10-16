package mysqlwire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildMockHandshakeResponse(flags uint32, username, auth, dbName, plugin string) []byte {
	var buf bytes.Buffer

	// 4 bytes flags
	var f [4]byte
	binary.LittleEndian.PutUint32(f[:], flags)
	buf.Write(f[:])

	// 4 bytes max packet
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	// 1 byte charset
	buf.WriteByte(33) // utf8
	// 23 bytes zeros
	buf.Write(make([]byte, 23))

	// username
	buf.WriteString(username)
	buf.WriteByte(0)

	// auth data
	if flags&ClientSecureConnection != 0 {
		buf.WriteByte(byte(len(auth)))
		buf.WriteString(auth)
	} else {
		buf.WriteString(auth)
		buf.WriteByte(0)
	}

	// db name
	if flags&ClientConnectWithDB != 0 {
		buf.WriteString(dbName)
		buf.WriteByte(0)
	}

	// plugin name
	if flags&ClientPluginAuth != 0 {
		buf.WriteString(plugin)
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

func TestReadWritePacket(t *testing.T) {
	payload := []byte("hello mysql world")
	var buf bytes.Buffer

	err := WritePacket(&buf, payload, 1)
	if err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	readPayload, seqID, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}

	if seqID != 1 {
		t.Errorf("expected seqID=1, got %d", seqID)
	}
	if !bytes.Equal(readPayload, payload) {
		t.Errorf("payload mismatch: got %q, want %q", readPayload, payload)
	}
}

func TestRewriteHandshakeResponseDatabase(t *testing.T) {
	flags := ClientProtocol41 | ClientSecureConnection | ClientConnectWithDB | ClientPluginAuth
	originalPacket := buildMockHandshakeResponse(flags, "root", "authpass123", "original_db", "mysql_native_password")

	rewritten, err := RewriteHandshakeResponseDatabase(originalPacket, "branch_db_feat_x")
	if err != nil {
		t.Fatalf("RewriteHandshakeResponseDatabase failed: %v", err)
	}

	if !bytes.Contains(rewritten, []byte("branch_db_feat_x\x00")) {
		t.Errorf("expected rewritten packet to contain target database, got %q", rewritten)
	}
	if bytes.Contains(rewritten, []byte("original_db\x00")) {
		t.Errorf("rewritten packet still contains original_db")
	}
	if !bytes.Contains(rewritten, []byte("mysql_native_password\x00")) {
		t.Errorf("rewritten packet corrupted trailing plugin auth name")
	}
}

func TestRewriteHandshakeResponseDatabaseInjectWhenMissing(t *testing.T) {
	flags := ClientProtocol41 | ClientSecureConnection | ClientPluginAuth // NO ClientConnectWithDB
	originalPacket := buildMockHandshakeResponse(flags, "root", "authpass123", "", "mysql_native_password")

	rewritten, err := RewriteHandshakeResponseDatabase(originalPacket, "injected_branch_db")
	if err != nil {
		t.Fatalf("RewriteHandshakeResponseDatabase failed: %v", err)
	}

	// Verify ClientConnectWithDB flag is now enabled
	newFlags := binary.LittleEndian.Uint32(rewritten[0:4])
	if newFlags&ClientConnectWithDB == 0 {
		t.Errorf("expected ClientConnectWithDB flag to be set in rewritten packet")
	}

	if !bytes.Contains(rewritten, []byte("injected_branch_db\x00")) {
		t.Errorf("expected rewritten packet to contain injected database, got %q", rewritten)
	}
}

func TestRewriteHandshakeResponseShortPacket(t *testing.T) {
	shortPayload := []byte{0x01, 0x02, 0x03}
	_, err := RewriteHandshakeResponseDatabase(shortPayload, "target")
	if err == nil {
		t.Errorf("expected error on short payload, got nil")
	}
}

func TestBuildErrorPacket(t *testing.T) {
	errPkt := BuildErrorPacket(1049, "42000", "Unknown database 'test_db'", 2)
	if len(errPkt) < 4 {
		t.Fatalf("expected packet length >= 4, got %d", len(errPkt))
	}

	payloadLen := int(errPkt[0]) | int(errPkt[1])<<8 | int(errPkt[2])<<16
	seqID := errPkt[3]
	if seqID != 2 {
		t.Errorf("expected seqID=2, got %d", seqID)
	}
	if payloadLen != len(errPkt)-4 {
		t.Errorf("header length %d does not match actual payload length %d", payloadLen, len(errPkt)-4)
	}

	payload := errPkt[4:]
	if payload[0] != 0xFF {
		t.Errorf("expected 0xFF header byte for ERR packet, got 0x%X", payload[0])
	}
	errCode := binary.LittleEndian.Uint16(payload[1:3])
	if errCode != 1049 {
		t.Errorf("expected error code 1049, got %d", errCode)
	}
	if payload[3] != '#' {
		t.Errorf("expected '#' SQLSTATE marker, got %c", payload[3])
	}
	sqlState := string(payload[4:9])
	if sqlState != "42000" {
		t.Errorf("expected SQLSTATE '42000', got %q", sqlState)
	}
	msg := string(payload[9:])
	if msg != "Unknown database 'test_db'" {
		t.Errorf("expected message %q, got %q", "Unknown database 'test_db'", msg)
	}
}

func TestReadPacketExceedsMaxHandshakePacketSize(t *testing.T) {
	// Construct a header with payloadLen > MaxHandshakePacketSize (e.g. 2 MB)
	oversizedLen := MaxHandshakePacketSize + 1024
	header := [4]byte{
		byte(oversizedLen),
		byte(oversizedLen >> 8),
		byte(oversizedLen >> 16),
		1,
	}
	var buf bytes.Buffer
	buf.Write(header[:])

	_, _, err := ReadPacket(&buf)
	if err == nil {
		t.Fatal("expected error on oversized packet, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("exceeds safety limit")) {
		t.Fatalf("expected ErrPacketTooLarge error, got: %v", err)
	}
}

func TestRewriteHandshakeResponse_LargeLenencAuthDoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	flags := ClientProtocol41 | ClientPluginAuthLenencClientData | ClientConnectWithDB

	// 4 bytes flags
	var f [4]byte
	binary.LittleEndian.PutUint32(f[:], flags)
	buf.Write(f[:])

	// 4 bytes max packet + 1 byte charset + 23 bytes zeros
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	buf.WriteByte(33)
	buf.Write(make([]byte, 23))

	// username
	buf.WriteString("root\x00")

	// 0xfe marker followed by 0x8000000000000000 (negative int64)
	buf.WriteByte(0xfe)
	var largeLen [8]byte
	binary.LittleEndian.PutUint64(largeLen[:], 0x8000000000000000)
	buf.Write(largeLen[:])

	// Dummy db
	buf.WriteString("testdb\x00")

	packet := buf.Bytes()

	// Should safely return an error without panicking
	_, err := RewriteHandshakeResponseDatabase(packet, "newdb")
	if err == nil {
		t.Fatal("expected error on invalid packet with huge lenenc auth, got nil")
	}
}

func TestValidateDatabaseIdentifier(t *testing.T) {
	validNames := []string{
		"valid_db",
		"branch_123",
		"feature-login",
		"db",
	}
	for _, name := range validNames {
		if err := ValidateDatabaseIdentifier(name); err != nil {
			t.Errorf("expected valid identifier for %q, got err: %v", name, err)
		}
	}

	invalidNames := []struct {
		name string
		desc string
	}{
		{"", "empty identifier"},
		{"a_very_long_database_identifier_that_exceeds_sixty_four_characters_limit_12345", "exceeds 64 chars"},
		{"db\x00injection", "null byte"},
		{"db;DROP TABLE users", "semicolon"},
		{"db/slash", "forward slash"},
		{"db\\backslash", "backward slash"},
	}
	for _, tc := range invalidNames {
		if err := ValidateDatabaseIdentifier(tc.name); err == nil {
			t.Errorf("expected error for %s (%q), got nil", tc.desc, tc.name)
		}
	}
}

func FuzzRewriteHandshakeResponseDatabase(f *testing.F) {
	// Seed with basic packets
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})

	// Seed with a valid packet structure
	var buf bytes.Buffer
	var fl [4]byte
	binary.LittleEndian.PutUint32(fl[:], ClientProtocol41|ClientConnectWithDB)
	buf.Write(fl[:])
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01, 33})
	buf.Write(make([]byte, 23))
	buf.WriteString("root\x00")
	buf.WriteString("pass\x00")
	buf.WriteString("mydb\x00")
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		// Attempt rewrite on arbitrary input; it must never panic
		_, _ = RewriteHandshakeResponseDatabase(data, "fuzz_db")
	})
}

