// http://www.ietf.org/rfc/rfc1928.txt
package shadysocks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/uber-go/zap"
)

const (
	socks5Ver = uint8(0x05) // PROTOCOL VERSION: X'05'

	// X'00' NO AUTHENTICATION REQUIRED
	// X'01' GSSAPI
	// X'02' USERNAME/PASSWORD
	// X'03' to X'7F' IANA ASSIGNED
	// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	// X'FF' NO ACCEPTABLE METHODS
	noAuth       = uint8(0x00)
	noAcceptable = uint8(0xFF)

	// IP V4 address: X'01'
	// DOMAINNAME: X'03'
	// IP V6 address: X'04'
	ipv4 = uint8(0x01)
	fqdn = uint8(0x03)
	ipv6 = uint8(0x04)

	// CONNECT X'01'
	// BIND X'02'
	// UDP ASSOCIATE X'03'
	connect = uint8(0x01)
	bind    = uint8(0x02)
	udp     = uint8(0x03)
)

// TODO
type dstAddr struct {
	fqdn   string
	ip     net.IP
	port   int
	octets []byte
}

func readDstAddr(r io.Reader) (*dstAddr, error) {
	var buf bytes.Buffer
	tee := io.TeeReader(r, &buf)

	dst := &dstAddr{}
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(tee, atyp); err != nil {
		return nil, err
	}
	test := atyp[0] & otaTestMask
	if test != 0x00 && test != otaFlag {
		err := fmt.Errorf("test address type failed: %v", atyp[0])
		return nil, err
	}

	// ATYP is a 8-bit char where the rightmost four bits,
	// 0b00001111 (0xf), are reserved for address types,
	// the flag bit of OTA is 0b00010000 (0x10).
	switch atyp[0] & otaMask {
	case ipv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(tee, addr); err != nil {
			return nil, err
		}
		dst.ip = net.IP(addr)
	case fqdn:
		l := []byte{0}
		if _, err := io.ReadFull(tee, l); err != nil {
			return nil, err
		}
		hostname := make([]byte, l[0])
		if _, err := io.ReadFull(tee, hostname); err != nil {
			return nil, err
		}
		dst.fqdn = string(hostname)
	case ipv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(tee, addr); err != nil {
			return nil, err
		}
		dst.ip = net.IP(addr)
	default:
		err := fmt.Errorf("unknown address type: %v", atyp[0]&otaMask)
		return nil, err
	}

	port := make([]byte, 2)
	if _, err := io.ReadFull(tee, port); err != nil {
		return nil, err
	}
	dst.port = int(binary.BigEndian.Uint16(port))
	dst.octets = buf.Bytes()
	return dst, nil
}

func handleMethod(conn io.ReadWriteCloser) error {
	// TODO: 这个地方如果socks5-cli自己实现，三个字段都可以固定下来

	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	ver, nmethods := header[0], int(header[1])
	logger.Debug("read method:", zap.Int("ver", int(ver)), zap.Int("nmethods", nmethods))
	if ver != socks5Ver {
		err := fmt.Errorf("Unsupported SOCKS version: %v", ver)
		return err
	}

	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	if nmethods <= 0 {
		err := fmt.Errorf("Invalid NMETHODS: %v", nmethods)
		conn.Write([]byte{socks5Ver, noAcceptable})
		return err
	}

	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		conn.Write([]byte{socks5Ver, noAcceptable})
		return err
	}
	if !checkNoAuth(methods) {
		err := fmt.Errorf("No noauth method")
		conn.Write([]byte{socks5Ver, noAcceptable})
		return err
	}

	conn.Write([]byte{socks5Ver, noAuth})
	return nil
}

func checkNoAuth(methods []byte) bool {
	found := false
	for method := range methods {
		logger.Debug("", zap.Int("method", method))
		// TODO: no break for debugging
		if uint8(method) == noAuth {
			found = true
		}
	}

	logger.Debug("checkNoAuth", zap.Bool("noauth", found))
	return found
}

func handleRequest(conn io.ReadWriteCloser, srv Node) error {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("Failed to get request header: %v", err)
	}

	ver, cmd, rsv := header[0], header[1], header[2]
	logger.Debug("request header", zap.Int("ver", int(ver)), zap.Int("cmd", int(cmd)), zap.Int("rsv", int(rsv)))
	if ver != socks5Ver || rsv != 0x00 {
		err := fmt.Errorf("Invalid request header, ver: %v, rsv: %v", ver, rsv)
		return err
	}
	dstAddr, err := readDstAddr(conn)
	if err != nil {
		return err
	}
	logger.Debug("handleRequest", zap.String("FQDN", dstAddr.fqdn), zap.String("IP", dstAddr.ip.String()), zap.Int("Port", dstAddr.port))

	switch cmd {
	case connect:
		logger.Debug("connect")
		handleConnect(conn, dstAddr, srv)
	case bind:
		logger.Panic("bind unimplemented!")
	case udp:
		// TODO: 客户端只能使用dstAddr的地址和端口发送数据，
		// 如果不验证客户端来源就不需要解析dstAddr
		logger.Debug("udp associate")
		handleUDPAssociate(conn, srv)
	default:
		logger.Panic("unknown request cmd")
	}
	return nil
}

func handleConnect(conn io.ReadWriteCloser, dst *dstAddr, srv Node) error {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x10, 0x10})

	rconn, err := srv.DialTCP()
	if err != nil {
		return err
	}

	// request
	rconn.Write(dst.octets)

	proxy(conn, rconn)
	return nil
}

func HandleSocks5TCP(conn io.ReadWriteCloser, srv Node) error {
	if err := handleMethod(conn); err != nil {
		return err
	}
	if err := handleRequest(conn, srv); err != nil {
		return err
	}
	return nil
}

func handleUDPAssociate(conn io.ReadWriteCloser, srv Node) error {
	var buf bytes.Buffer
	buf.Write([]byte{socks5Ver, 0x00, 0x00})
	if ip := srv.LocalUDPAddr().IP.To4(); ip != nil {
		buf.WriteByte(ipv4)
		buf.Write(ip)
	} else if len(srv.LocalUDPAddr().IP) == net.IPv6len {
		buf.WriteByte(ipv6)
		buf.Write(srv.LocalUDPAddr().IP)
	} else {
		err := fmt.Errorf("wrong ip length: %v", len(srv.LocalUDPAddr().IP))
		return err
	}

	err := binary.Write(&buf, binary.BigEndian, uint16(srv.LocalUDPAddr().Port))
	if err != nil {
		return err
	}
	conn.Write(buf.Bytes())

	return nil
}

func HandleSocks5UDP(conn net.PacketConn, saddr net.Addr, packet []byte, srv Node) error {
	if packet[2] != 0x00 {
		err := fmt.Errorf("drop any datagram whose frag is other than 0x00, frag: %v", packet[2])
		logger.Error("HandleSocks5UDP", zap.Error(err))
		return err
	}
	rconn, err := srv.DialUDP()
	if err != nil {
		return err
	}
	n, err := rconn.WriteTo(packet[3:], nil)
	if err != nil {
		return err
	}
	// TODO: need optimization here
	buf := make([]byte, 65535)
	for {
		n, _, err = rconn.ReadFrom(buf)
		if err != nil {
			return err
		}
		response := append([]byte{0x00, 0x00, 0x00}, buf[:n]...)
		n, err = conn.WriteTo(response, saddr)
		if err != nil {
			return err
		}
		logger.Info(fmt.Sprintf("sending %d bytes to %s", n, saddr))
	}
}
