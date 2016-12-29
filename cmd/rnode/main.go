package main

import (
	"net"
	"os"

	ss "github.com/en/shadysocks"
	"github.com/uber-go/zap"
	"gopkg.in/urfave/cli.v2"
)

var (
	logger = zap.New(
		zap.NewTextEncoder(),
		zap.DebugLevel,
	)
)

// rnode implements shadysocks.Node
type rnode struct {
	localTCPAddr *net.TCPAddr
	localUDPAddr *net.UDPAddr
	shadowsocks  *ss.Shadowsocks
}

func (srv *rnode) LocalTCPAddr() *net.TCPAddr {
	return srv.localTCPAddr
}

func (srv *rnode) LocalUDPAddr() *net.UDPAddr {
	return srv.localUDPAddr
}

func (srv *rnode) RemoteTCPAddr() *net.TCPAddr {
	return srv.shadowsocks.RemoteTCPAddr
}

func (srv *rnode) RemoteUDPAddr() *net.UDPAddr {
	return srv.shadowsocks.RemoteUDPAddr
}

func (srv *rnode) DialTCP() (net.Conn, error) {
	return srv.shadowsocks.DialTCP()
}

func (srv *rnode) DialUDP() (net.PacketConn, error) {
	return srv.shadowsocks.DialUDP()
}

func (srv *rnode) init(conf *ss.Config) error {
	var err error
	srv.localTCPAddr, err = net.ResolveTCPAddr("tcp", conf.Rnode)
	if err != nil {
		return err
	}

	srv.localUDPAddr, err = net.ResolveUDPAddr("udp", conf.Rnode)
	if err != nil {
		return err
	}

	otaStatus := ss.OTADisabled
	if conf.OneTimeAuth {
		otaStatus = ss.OTASenderRequest
	}
	srv.shadowsocks, err = ss.NewShadowsocks(conf.Pnode, conf.Method, conf.Password, otaStatus)
	if err != nil {
		return err
	}
	return nil
}

func (srv *rnode) serve() error {
	go srv.serveTCP()
	go srv.serveUDP()

	select {}
}

func (srv *rnode) serveTCP() {
	l, err := net.ListenTCP("tcp", srv.localTCPAddr)
	if err != nil {
		logger.Fatal("serveTCP", zap.Error(err))
	}
	defer l.Close()
	logger.Info("listening TCP on " + srv.localTCPAddr.String())

	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			logger.Warn("Accept TCP failed", zap.Error(err))
			continue
		}
		go srv.handleTCPConn(conn)
	}
}

func (srv *rnode) handleTCPConn(conn net.Conn) {
	if err := ss.HandleSocks5TCP(conn, srv); err != nil {
		logger.Error("HandleSocks5TCP", zap.Error(err))
	}
}

func (srv *rnode) serveUDP() {
	conn, err := net.ListenUDP("udp", srv.localUDPAddr)
	if err != nil {
		logger.Fatal("serveUDP", zap.Error(err))
	}
	logger.Info("listening UDP on " + srv.localUDPAddr.String())

	buf := make([]byte, 65535)
	for {
		n, saddr, err := conn.ReadFrom(buf)
		if err != nil {
			logger.Warn("ReadFrom UDP failed", zap.Error(err))
			continue
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go srv.handleUDPConn(conn, saddr, packet)
	}
}

func (srv *rnode) handleUDPConn(conn net.PacketConn, saddr net.Addr, packet []byte) {
	if err := ss.HandleSocks5UDP(conn, saddr, packet, srv); err != nil {
		logger.Error("HandleSocks5UDP", zap.Error(err))
	}
}

func main() {
	app := &cli.App{
		Name:  "shadysocks-rnode",
		Usage: "",
		Action: func(c *cli.Context) error {
			// TODO
			path := "config.toml"
			var conf ss.Config
			if err := ss.ParseConfig(path, &conf); err != nil {
				return err
			}

			srv := new(rnode)
			if err := srv.init(&conf); err != nil {
				return err
			}

			return srv.serve()
		},
	}

	app.Run(os.Args)
}
