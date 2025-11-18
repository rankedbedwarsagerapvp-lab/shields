package minecraft

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const (
	PacketHandshake      = 0x00
	PacketStatusRequest  = 0x00
	PacketStatusResponse = 0x00
	PacketPingRequest    = 0x01
	PacketPingResponse   = 0x01
	PacketLoginStart     = 0x00

	StateHandshaking = 0
	StateStatus      = 1
	StateLogin       = 2
	StatePlay        = 3
)

type Packet struct {
	Length   int32
	PacketID int32
	Data     []byte
}

type HandshakePacket struct {
	ProtocolVersion int32
	ServerAddress   string
	ServerPort      uint16
	NextState       int32
}

type StatusResponse struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players struct {
		Max    int `json:"max"`
		Online int `json:"online"`
	} `json:"players"`
	Description interface{} `json:"description"`
	Favicon     string      `json:"favicon,omitempty"`
}

// ReadVarInt reads a variable-length integer from the reader
func ReadVarInt(r io.Reader) (int32, error) {
	var result int32
	var numRead uint

	for {
		if numRead > 5 {
			return 0, errors.New("VarInt is too big")
		}

		buf := make([]byte, 1)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}

		value := buf[0]
		result |= int32(value&0x7F) << (7 * numRead)
		numRead++

		if (value & 0x80) == 0 {
			break
		}
	}

	return result, nil
}

// WriteVarInt writes a variable-length integer to the writer
func WriteVarInt(w io.Writer, value int32) error {
	for {
		if (value & ^0x7F) == 0 {
			return binary.Write(w, binary.BigEndian, byte(value))
		}

		if err := binary.Write(w, binary.BigEndian, byte((value&0x7F)|0x80)); err != nil {
			return err
		}

		value >>= 7
	}
}

// ReadString reads a Minecraft string (VarInt length + UTF-8 string)
func ReadString(r io.Reader, maxLen int) (string, error) {
	length, err := ReadVarInt(r)
	if err != nil {
		return "", err
	}

	if length < 0 || length > int32(maxLen) {
		return "", errors.New("string length out of bounds")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

// WriteString writes a Minecraft string
func WriteString(w io.Writer, s string) error {
	if err := WriteVarInt(w, int32(len(s))); err != nil {
		return err
	}
	_, err := w.Write([]byte(s))
	return err
}

// ReadPacket reads a full Minecraft packet
func ReadPacket(r io.Reader, maxSize int) (*Packet, error) {
	length, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	if length <= 0 || length > int32(maxSize) {
		return nil, errors.New("packet length out of bounds")
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	buf := bytes.NewReader(data)
	packetID, err := ReadVarInt(buf)
	if err != nil {
		return nil, err
	}

	packetData := make([]byte, buf.Len())
	if _, err := io.ReadFull(buf, packetData); err != nil && err != io.EOF {
		return nil, err
	}

	return &Packet{
		Length:   length,
		PacketID: packetID,
		Data:     packetData,
	}, nil
}

// WritePacket writes a full Minecraft packet
func WritePacket(w io.Writer, packetID int32, data []byte) error {
	buf := new(bytes.Buffer)
	if err := WriteVarInt(buf, packetID); err != nil {
		return err
	}
	buf.Write(data)

	packetData := buf.Bytes()
	if err := WriteVarInt(w, int32(len(packetData))); err != nil {
		return err
	}

	_, err := w.Write(packetData)
	return err
}

// ParseHandshake parses a handshake packet
func ParseHandshake(data []byte) (*HandshakePacket, error) {
	buf := bytes.NewReader(data)

	protocolVersion, err := ReadVarInt(buf)
	if err != nil {
		return nil, err
	}

	serverAddress, err := ReadString(buf, 255)
	if err != nil {
		return nil, err
	}

	var serverPort uint16
	if err := binary.Read(buf, binary.BigEndian, &serverPort); err != nil {
		return nil, err
	}

	nextState, err := ReadVarInt(buf)
	if err != nil {
		return nil, err
	}

	return &HandshakePacket{
		ProtocolVersion: protocolVersion,
		ServerAddress:   serverAddress,
		ServerPort:      serverPort,
		NextState:       nextState,
	}, nil
}

// CreateStatusResponse creates a status response packet
func CreateStatusResponse(version string, protocol int, maxPlayers, onlinePlayers int, description string, favicon string) ([]byte, error) {
	resp := StatusResponse{
		Version: struct {
			Name     string `json:"name"`
			Protocol int    `json:"protocol"`
		}{
			Name:     version,
			Protocol: protocol,
		},
		Players: struct {
			Max    int `json:"max"`
			Online int `json:"online"`
		}{
			Max:    maxPlayers,
			Online: onlinePlayers,
		},
		Description: map[string]string{"text": description},
		Favicon:     favicon,
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := WriteString(buf, string(jsonData)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
