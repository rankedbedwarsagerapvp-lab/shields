package haproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	// PROXY protocol v2 signature
	ProxyV2Signature = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"

	// Version and command
	ProxyV2VersionCommand = 0x20 // Version 2, PROXY command

	// Address families
	ProxyV2FamilyUnspec = 0x00
	ProxyV2FamilyINET   = 0x10
	ProxyV2FamilyINET6  = 0x20
	ProxyV2FamilyUnix   = 0x30

	// Transport protocols
	ProxyV2TransportUnspec = 0x00
	ProxyV2TransportStream = 0x01
	ProxyV2TransportDgram  = 0x02
)

type ProxyInfo struct {
	SourceIP        net.IP
	DestinationIP   net.IP
	SourcePort      uint16
	DestinationPort uint16
	IsIPv6          bool
}

// ReadProxyProtocolV2 reads HAProxy PROXY protocol v2 header
func ReadProxyProtocolV2(r io.Reader) (*ProxyInfo, error) {
	// Read signature (12 bytes)
	sig := make([]byte, 12)
	if _, err := io.ReadFull(r, sig); err != nil {
		return nil, err
	}

	if string(sig) != ProxyV2Signature {
		return nil, errors.New("invalid PROXY protocol v2 signature")
	}

	// Read version and command (1 byte)
	verCmd := make([]byte, 1)
	if _, err := io.ReadFull(r, verCmd); err != nil {
		return nil, err
	}

	version := (verCmd[0] & 0xF0) >> 4
	command := verCmd[0] & 0x0F

	if version != 2 {
		return nil, errors.New("unsupported PROXY protocol version")
	}

	// Command 0 = LOCAL (health check), Command 1 = PROXY
	if command != 1 {
		return nil, errors.New("PROXY protocol LOCAL command not supported")
	}

	// Read family and protocol (1 byte)
	famProto := make([]byte, 1)
	if _, err := io.ReadFull(r, famProto); err != nil {
		return nil, err
	}

	family := famProto[0] & 0xF0
	protocol := famProto[0] & 0x0F

	if protocol != ProxyV2TransportStream {
		return nil, errors.New("only stream protocol is supported")
	}

	// Read address length (2 bytes)
	var addrLen uint16
	if err := binary.Read(r, binary.BigEndian, &addrLen); err != nil {
		return nil, err
	}

	// Read addresses based on family
	info := &ProxyInfo{}

	switch family {
	case ProxyV2FamilyINET:
		// IPv4: src_addr (4) + dst_addr (4) + src_port (2) + dst_port (2) = 12 bytes
		if addrLen < 12 {
			return nil, errors.New("invalid address length for IPv4")
		}

		srcIP := make([]byte, 4)
		dstIP := make([]byte, 4)

		if _, err := io.ReadFull(r, srcIP); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, dstIP); err != nil {
			return nil, err
		}

		if err := binary.Read(r, binary.BigEndian, &info.SourcePort); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.BigEndian, &info.DestinationPort); err != nil {
			return nil, err
		}

		info.SourceIP = net.IP(srcIP)
		info.DestinationIP = net.IP(dstIP)
		info.IsIPv6 = false

		// Skip any remaining bytes (TLVs)
		if addrLen > 12 {
			extra := make([]byte, addrLen-12)
			if _, err := io.ReadFull(r, extra); err != nil {
				return nil, err
			}
		}

	case ProxyV2FamilyINET6:
		// IPv6: src_addr (16) + dst_addr (16) + src_port (2) + dst_port (2) = 36 bytes
		if addrLen < 36 {
			return nil, errors.New("invalid address length for IPv6")
		}

		srcIP := make([]byte, 16)
		dstIP := make([]byte, 16)

		if _, err := io.ReadFull(r, srcIP); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, dstIP); err != nil {
			return nil, err
		}

		if err := binary.Read(r, binary.BigEndian, &info.SourcePort); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.BigEndian, &info.DestinationPort); err != nil {
			return nil, err
		}

		info.SourceIP = net.IP(srcIP)
		info.DestinationIP = net.IP(dstIP)
		info.IsIPv6 = true

		// Skip any remaining bytes (TLVs)
		if addrLen > 36 {
			extra := make([]byte, addrLen-36)
			if _, err := io.ReadFull(r, extra); err != nil {
				return nil, err
			}
		}

	default:
		return nil, errors.New("unsupported address family")
	}

	return info, nil
}

// WriteProxyProtocolV2 writes HAProxy PROXY protocol v2 header
func WriteProxyProtocolV2(w io.Writer, info *ProxyInfo) error {
	buf := new(bytes.Buffer)

	// Write signature
	buf.WriteString(ProxyV2Signature)

	// Write version and command
	buf.WriteByte(ProxyV2VersionCommand | 0x01) // Version 2, PROXY command

	// Determine family and write family+protocol
	var family byte
	var addrLen uint16

	if info.IsIPv6 {
		family = ProxyV2FamilyINET6
		addrLen = 36
	} else {
		family = ProxyV2FamilyINET
		addrLen = 12
	}

	buf.WriteByte(family | ProxyV2TransportStream)

	// Write address length
	_ = binary.Write(buf, binary.BigEndian, addrLen)

	// Write addresses
	if info.IsIPv6 {
		buf.Write(info.SourceIP.To16())
		buf.Write(info.DestinationIP.To16())
	} else {
		buf.Write(info.SourceIP.To4())
		buf.Write(info.DestinationIP.To4())
	}

	// Write ports
	_ = binary.Write(buf, binary.BigEndian, info.SourcePort)
	_ = binary.Write(buf, binary.BigEndian, info.DestinationPort)

	// Write to output
	_, err := w.Write(buf.Bytes())
	return err
}

// IsTrustedProxy checks if the connection is from a trusted proxy
func IsTrustedProxy(remoteAddr string, trustedProxies []string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}

	remoteIP := net.ParseIP(ip)
	if remoteIP == nil {
		return false
	}

	for _, trusted := range trustedProxies {
		if _, ipnet, err := net.ParseCIDR(trusted); err == nil {
			if ipnet.Contains(remoteIP) {
				return true
			}
		} else if trustedIP := net.ParseIP(trusted); trustedIP != nil {
			if trustedIP.Equal(remoteIP) {
				return true
			}
		}
	}

	return false
}
