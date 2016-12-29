package shadysocks

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/uber-go/zap"
)

const (
	otaMask         = 0x0F
	otaTestMask     = 0xF0
	otaChunkDataLen = 2
	otaBytes        = 10
	otaChunkBytes   = 12
	otaFlag         = 0x10
)

const (
	OTADisabled = 1 << iota
	OTASenderRequest
	OTASenderChunk
	OTAReceiverRequest
	OTAReceiverChunk
)

type Shadowsocks struct {
	method   string
	password string
	crpt     *crypto

	RemoteTCPAddr *net.TCPAddr
	RemoteUDPAddr *net.UDPAddr

	otaStatus int
}

func NewShadowsocks(raddr, method, password string, otaStatus int) (*Shadowsocks, error) {
	var err error
	s := &Shadowsocks{}
	s.RemoteTCPAddr, err = net.ResolveTCPAddr("tcp", raddr)
	if err != nil {
		return nil, err
	}

	s.RemoteUDPAddr, err = net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, err
	}
	s.method = method
	s.password = password
	s.otaStatus = otaStatus

	return s, nil
}

func (ss *Shadowsocks) AcceptUDP(conn *net.UDPConn) (*shadowsocksPacketConn, error) {
	var err error
	spc := &shadowsocksPacketConn{}
	spc.conn = conn
	spc.crpt, err = newCrypto(ss.method, ss.password)
	if err != nil {
		return nil, err
	}
	spc.otaStatus = ss.otaStatus
	spc.otaEnabled = (spc.otaStatus != OTADisabled)
	return spc, nil
}

func (ss *Shadowsocks) DialUDP() (*shadowsocksPacketConn, error) {
	conn, err := net.DialUDP("udp", nil, ss.RemoteUDPAddr)
	if err != nil {
		return nil, err
	}
	return ss.AcceptUDP(conn)
}

func (ss *Shadowsocks) AcceptTCP(conn net.Conn) (*shadowsocksConn, error) {
	var err error
	sc := &shadowsocksConn{}
	sc.conn = conn
	sc.crpt, err = newCrypto(ss.method, ss.password)
	if err != nil {
		return nil, err
	}
	sc.otaStatus = ss.otaStatus
	sc.otaBuffHead = make([]byte, 0)
	sc.otaBuffData = make([]byte, 0)
	sc.otaEnabled = (sc.otaStatus != OTADisabled)

	return sc, nil
}

func (ss *Shadowsocks) DialTCP() (*shadowsocksConn, error) {
	conn, err := net.DialTCP("tcp", nil, ss.RemoteTCPAddr)
	if err != nil {
		return nil, err
	}
	return ss.AcceptTCP(conn)
}

// shadowsocksConn implements net.Conn interface
type shadowsocksConn struct {
	conn        net.Conn
	iv          []byte
	decryptIV   []byte
	crpt        *crypto
	otaStatus   int
	otaChunkIdx int
	otaLen      int
	otaBuffHead []byte
	otaBuffData []byte
	otaEnabled  bool
}

func (sc *shadowsocksConn) Read(b []byte) (n int, err error) {
	if sc.crpt.decrypter == nil {
		sc.decryptIV = make([]byte, sc.crpt.blockSize)
		c, err := sc.conn.Read(sc.decryptIV)
		if err != nil || c != sc.crpt.blockSize {
			logger.Error("read iv failed", zap.Int("len", c), zap.Error(err))
			return c, err
		}
		sc.crpt.decrypter = sc.crpt.newDecrypter(sc.crpt.block, sc.decryptIV)
	}

	c, err := sc.conn.Read(b)
	if err != nil && err != io.EOF {
		return c, err
	}
	// TODO: why?
	if c == 0 && err == io.EOF {
		return c, err
	}
	sc.crpt.decrypter.XORKeyStream(b, b[:c])

	if sc.otaStatus == OTAReceiverChunk {
		unchunk := sc.otaChunkData(b[:c])
		// TODO: ugly
		c = len(unchunk)
		copy(b, unchunk)
	}
	return c, nil
}

func (sc *shadowsocksConn) Write(b []byte) (n int, err error) {
	n = len(b)

	if sc.crpt.encrypter == nil {
		iv := make([]byte, sc.crpt.blockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			logger.Panic(err.Error())
		}
		logger.Debug("encrypt", zap.String("iv", fmt.Sprintf("% x", iv)))
		sc.iv = iv
	}
	switch sc.otaStatus {
	case OTASenderRequest:
		b = sc.otaRequest(b)
		sc.otaStatus = OTASenderChunk
	case OTASenderChunk:
		b = sc.otaChunk(b)
	}
	var ciphertext []byte
	if sc.crpt.encrypter == nil {
		sc.crpt.encrypter = sc.crpt.newEncrypter(sc.crpt.block, sc.iv)
		ciphertext = make([]byte, sc.crpt.blockSize+len(b))
		copy(ciphertext, sc.iv)
		sc.crpt.encrypter.XORKeyStream(ciphertext[sc.crpt.blockSize:], b)
	} else {
		ciphertext = make([]byte, len(b))
		sc.crpt.encrypter.XORKeyStream(ciphertext, b)
	}
	c, err := sc.conn.Write(ciphertext)
	if err != nil {
		logger.Warn("shadowsocksConn", zap.Int("c", c), zap.Error(err))
	}
	return n, err
}

func (sc *shadowsocksConn) Close() error {
	sc.crpt.encrypter = nil
	sc.crpt.decrypter = nil
	return sc.conn.Close()
}

func (sc *shadowsocksConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

func (sc *shadowsocksConn) RemoteAddr() net.Addr {
	return sc.conn.RemoteAddr()
}

func (sc *shadowsocksConn) SetDeadline(t time.Time) error {
	return sc.conn.SetDeadline(t)
}

func (sc *shadowsocksConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

func (sc *shadowsocksConn) SetWriteDeadline(t time.Time) error {
	return sc.conn.SetWriteDeadline(t)
}

// https://shadowsocks.org/en/spec/one-time-auth.html
func (sc *shadowsocksConn) otaRequest(data []byte) []byte {
	// +------+----------+----------+-----------+
	// | ATYP | DST.ADDR | DST.PORT | HMAC-SHA1 |
	// +------+----------+----------+-----------+
	// |  1   | Variable |    2     |    10     |
	// +------+----------+----------+-----------+
	data[0] |= otaFlag
	key := append(sc.iv, sc.crpt.key...)
	sha110 := hmacsha1(key, data)[:otaBytes]
	return append(data, sha110...)
}

func (sc *shadowsocksConn) otaChunk(data []byte) []byte {
	// +----------+-----------+----------+
	// | DATA.LEN | HMAC-SHA1 |   DATA   |
	// +----------+-----------+----------+
	// |    2     |    10     | Variable |
	// +----------+-----------+----------+
	l := len(data)
	chunk := make([]byte, 2+otaBytes+l)
	binary.BigEndian.PutUint16(chunk[:2], uint16(l))

	key := make([]byte, sc.crpt.blockSize+4)
	copy(key, sc.iv)
	binary.BigEndian.PutUint32(key[sc.crpt.blockSize:], uint32(sc.otaChunkIdx))

	sha110 := hmacsha1(key, data)[:otaBytes]
	sc.otaChunkIdx++

	copy(chunk[2:], sha110)
	copy(chunk[12:], data)
	return chunk
}

func (sc *shadowsocksConn) otaChunkData(data []byte) []byte {
	unchunk := make([]byte, 0)
	// TODO: ugly
	for len(data) > 0 {
		if sc.otaLen == 0 {
			length := otaChunkBytes - len(sc.otaBuffHead)
			sc.otaBuffHead = append(sc.otaBuffHead, data[:length]...)
			data = data[length:]
			if len(sc.otaBuffHead) < otaChunkBytes {
				return nil
			}
			sc.otaLen = int(binary.BigEndian.Uint16(sc.otaBuffHead[:otaChunkDataLen]))
		}
		length := sc.otaLen - len(sc.otaBuffData)
		if len(data) < length {
			length = len(data)
		}
		sc.otaBuffData = append(sc.otaBuffData, data[:length]...)
		data = data[length:]
		if len(sc.otaBuffData) == sc.otaLen {
			key := make([]byte, sc.crpt.blockSize+4)
			copy(key, sc.decryptIV)
			binary.BigEndian.PutUint32(key[sc.crpt.blockSize:], uint32(sc.otaChunkIdx))
			if otaVerify(key, sc.otaBuffData, sc.otaBuffHead[otaChunkDataLen:]) {
				logger.Debug("one time auth success")
				unchunk = append(unchunk, sc.otaBuffData...)
				sc.otaChunkIdx++
			} else {
				logger.Warn("one time auth failed, drop chunk")
			}
			sc.otaLen = 0
			sc.otaBuffHead = make([]byte, 0)
			sc.otaBuffData = make([]byte, 0)
		}
	}
	return unchunk
}

// TODO: ugly
func HandleShadowsocksTCP(sc *shadowsocksConn) error {
	dstAddr, err := readDstAddr(sc)
	if err != nil {
		return err
	}
	logger.Debug("HandleShadowsocksTCP", zap.String("FQDN", dstAddr.fqdn), zap.String("IP", dstAddr.ip.String()), zap.Int("Port", dstAddr.port))
	// TODO: ugly
	if (dstAddr.octets[0] & otaFlag) != 0 {
		sc.otaStatus = OTAReceiverRequest
		hash := make([]byte, otaBytes)
		if _, err := io.ReadFull(sc, hash); err != nil {
			return err
		}
		key := append(sc.decryptIV, sc.crpt.key...)
		if !otaVerify(key, dstAddr.octets, hash) {
			err := fmt.Errorf("one time auth failed")
			return err
		}
		sc.otaStatus = OTAReceiverChunk
	} else {
		if sc.otaEnabled {
			err := fmt.Errorf("one time auth is required")
			return err
		}
		sc.otaStatus = OTADisabled
	}

	var dst string
	if dstAddr.ip != nil {
		dst = net.JoinHostPort(dstAddr.ip.String(), fmt.Sprintf("%d", dstAddr.port))
	} else if dstAddr.fqdn != "" {
		dst = net.JoinHostPort(dstAddr.fqdn, fmt.Sprintf("%d", dstAddr.port))
	}
	dstTCPAddr, err := net.ResolveTCPAddr("tcp", dst)
	if err != nil {
		return err
	}
	rconn, err := net.DialTCP("tcp", nil, dstTCPAddr)
	if err != nil {
		return err
	}

	proxy(rconn, sc)

	return nil
}

// shadowsocksPacketConn implements net.PacketConn interface
type shadowsocksPacketConn struct {
	conn       *net.UDPConn
	crpt       *crypto
	otaStatus  int
	otaEnabled bool
}

func (spc *shadowsocksPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// TODO: ugly
	// TODO: check len(b)?
	n, addr, err = spc.conn.ReadFrom(b)
	if err != nil {
		return
	}
	_, data := spc.decrypt(b[:n])
	copy(b, data)
	return len(data), addr, nil
}

func (spc *shadowsocksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// TODO: ugly
	cipherdata := spc.encrypt(b)
	if addr == nil {
		return spc.conn.Write(cipherdata)
	}
	return spc.conn.WriteTo(cipherdata, addr)
}

func (spc *shadowsocksPacketConn) Close() error {
	return spc.conn.Close()
}

func (spc *shadowsocksPacketConn) LocalAddr() net.Addr {
	return spc.conn.LocalAddr()
}

func (spc *shadowsocksPacketConn) SetDeadline(t time.Time) error {
	return spc.conn.SetDeadline(t)
}

func (spc *shadowsocksPacketConn) SetReadDeadline(t time.Time) error {
	return spc.conn.SetReadDeadline(t)
}

func (spc *shadowsocksPacketConn) SetWriteDeadline(t time.Time) error {
	return spc.conn.SetWriteDeadline(t)
}

func (spc *shadowsocksPacketConn) decrypt(b []byte) ([]byte, []byte) {
	var data []byte
	c := len(b)
	if c < spc.crpt.blockSize {
		logger.Panic("ciphertext too short", zap.Int("len", c))
	}
	data = b[spc.crpt.blockSize:c]
	logger.Debug("decrypt", zap.String("iv", fmt.Sprintf("% x", b[:spc.crpt.blockSize])))
	decrypter := spc.crpt.newDecrypter(spc.crpt.block, b[:spc.crpt.blockSize])
	c = c - spc.crpt.blockSize
	// TODO: xor in place?
	ret := make([]byte, c)
	decrypter.XORKeyStream(ret, data)
	return b[:spc.crpt.blockSize], ret
}

func (spc *shadowsocksPacketConn) encrypt(src []byte) []byte {
	iv := make([]byte, spc.crpt.blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		logger.Panic(err.Error())
		return nil
	}
	logger.Debug("encrypt", zap.String("iv", fmt.Sprintf("% x", iv)))
	encrypter := spc.crpt.newEncrypter(spc.crpt.block, iv)
	var data []byte
	if spc.otaStatus == OTASenderRequest {
		data = spc.otaChunkUDP(iv, src)
	} else {
		data = src
	}
	ciphertext := make([]byte, spc.crpt.blockSize+len(data))
	copy(ciphertext, iv)
	encrypter.XORKeyStream(ciphertext[spc.crpt.blockSize:], data)

	return ciphertext
}

func (spc *shadowsocksPacketConn) otaChunkUDP(iv, data []byte) []byte {
	// +------+----------+----------+----------+-----------+
	// | ATYP | DST.ADDR | DST.PORT |   DATA   | HMAC-SHA1 |
	// +------+----------+----------+----------+-----------+
	// |  1   | Variable |    2     | Variable |    10     |
	// +------+----------+----------+----------+-----------+
	data[0] |= otaFlag
	h := hmacsha1(append(iv, spc.crpt.key...), data)[:otaBytes]
	return append(data, h...)
}

func (spc *shadowsocksPacketConn) HandleShadowsocksUDP(saddr net.Addr, packet []byte) error {
	iv, data := spc.decrypt(packet)
	reader := bytes.NewReader(data)
	dstAddr, err := readDstAddr(reader)
	if err != nil {
		return err
	}
	logger.Debug("HandleShadowsocksUDP", zap.String("FQDN", dstAddr.fqdn), zap.String("IP", dstAddr.ip.String()), zap.Int("Port", dstAddr.port))
	var dst string
	if dstAddr.ip != nil {
		dst = net.JoinHostPort(dstAddr.ip.String(), fmt.Sprintf("%d", dstAddr.port))
	} else if dstAddr.fqdn != "" {
		dst = net.JoinHostPort(dstAddr.fqdn, fmt.Sprintf("%d", dstAddr.port))
	}
	daddr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		return err
	}

	rconn, err := net.DialUDP("udp", nil, daddr)
	if err != nil {
		return err
	}
	// TODO: ugly
	b := make([]byte, 65535)
	n, err := reader.Read(b)
	if err != nil {
		return err
	}
	// ota verify
	if (dstAddr.octets[0] & otaFlag) != 0 {
		if n < otaBytes {
			err := fmt.Errorf("UDP one time auth header is too short")
			return err
		}
		hash := b[n-otaBytes : n]
		n -= otaBytes
		message := append(dstAddr.octets, b[:n]...)
		key := append(iv, spc.crpt.key...)
		if !otaVerify(key, message, hash) {
			err := fmt.Errorf("one time auth failed")
			return err
		}
	} else {
		if spc.otaEnabled {
			err := fmt.Errorf("one time auth is required")
			return err
		}
	}

	n, err = rconn.Write(b[:n])
	if err != nil {
		return err
	}
	for {
		n, raddr, err := rconn.ReadFrom(b)
		if err != nil {
			return err
		}
		ruaddr, err := net.ResolveUDPAddr("udp", raddr.String())
		if err != nil {
			return err
		}

		var buff bytes.Buffer
		if ip := ruaddr.IP.To4(); ip != nil {
			// TODO: ugly
			buff.WriteByte(0x01) // ipv4
			buff.Write(ip)
		} else if len(ruaddr.IP) == net.IPv6len {
			buff.WriteByte(0x04) // ipv6
			buff.Write(ruaddr.IP)
		} else {
			err := fmt.Errorf("wrong ip length: %v", len(ruaddr.IP))
			return err
		}

		err = binary.Write(&buff, binary.BigEndian, uint16(ruaddr.Port))
		if err != nil {
			return err
		}
		// TODO: ugly
		data := append(buff.Bytes(), b[:n]...)

		n, err = spc.WriteTo(data, saddr)
		if err != nil {
			return err
		}
		logger.Info(fmt.Sprintf("sending %d bytes to %s", n, saddr))
	}
	return nil
}

// TODO: move to utils?
// HMAC-SHA1
func hmacsha1(key, message []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func otaVerify(key, message, hash []byte) bool {
	mac := hmacsha1(key, message)[:otaBytes]
	logger.Debug("OTA verify", zap.String("cli", fmt.Sprintf("% x", hash)),
		zap.String("srv", fmt.Sprintf("% x", mac)))
	return bytes.Compare(mac, hash) == 0
}

// taken from kcptun
func proxy(p1, p2 io.ReadWriteCloser) {
	logger.Debug("stream opened")
	defer logger.Debug("stream closed")

	defer p1.Close()
	defer p2.Close()

	p1die := make(chan struct{})
	go func() {
		io.Copy(p1, p2)
		close(p1die)
	}()

	p2die := make(chan struct{})
	go func() {
		io.Copy(p2, p1)
		close(p2die)
	}()

	select {
	case <-p1die:
	case <-p2die:
	}
}
