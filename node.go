package shadysocks

import (
	"net"
)

type Node interface {
	LocalTCPAddr() *net.TCPAddr
	LocalUDPAddr() *net.UDPAddr

	RemoteTCPAddr() *net.TCPAddr
	RemoteUDPAddr() *net.UDPAddr

	DialTCP() (net.Conn, error)
	DialUDP() (net.PacketConn, error)
}
