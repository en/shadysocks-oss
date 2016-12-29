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

type pnode struct {
	localTCPAddr *net.TCPAddr
	localUDPAddr *net.UDPAddr
	shadowsocks  *ss.Shadowsocks
}

func (srv *pnode) init(conf *ss.Config) error {
	var err error
	srv.localTCPAddr, err = net.ResolveTCPAddr("tcp", conf.Pnode)
	if err != nil {
		return err
	}

	srv.localUDPAddr, err = net.ResolveUDPAddr("udp", conf.Pnode)
	if err != nil {
		return err
	}

	otaStatus := ss.OTADisabled
	if conf.OneTimeAuth {
		otaStatus = ss.OTAReceiverRequest
	}
	srv.shadowsocks, err = ss.NewShadowsocks(conf.Rnode, conf.Method, conf.Password, otaStatus)
	if err != nil {
		return err
	}
	return nil
}

func (srv *pnode) serve() error {
	go srv.serveTCP()
	go srv.serveUDP()

	select {}
}

func (srv *pnode) serveTCP() {
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

func (srv *pnode) handleTCPConn(conn net.Conn) {
	sc, err := srv.shadowsocks.AcceptTCP(conn)
	if err != nil {
		logger.Error("acceptTCP shadowsocks failed", zap.Error(err))
		return
	}

	if err := ss.HandleShadowsocksTCP(sc); err != nil {
		logger.Error("HandleShadowsocksTCP", zap.Error(err))
	}
}

func (srv *pnode) serveUDP() {
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

func (srv *pnode) handleUDPConn(conn *net.UDPConn, saddr net.Addr, packet []byte) {
	spc, err := srv.shadowsocks.AcceptUDP(conn)
	if err != nil {
		logger.Error("acceptUDP shadowsocks failed", zap.Error(err))
		return
	}
	if err := spc.HandleShadowsocksUDP(saddr, packet); err != nil {
		logger.Error("HandleShadowsocksUDP", zap.Error(err))
	}
}

func main() {
	app := &cli.App{
		Name:  "shadysocks-pnode",
		Usage: "",
		Action: func(c *cli.Context) error {
			// TODO
			path := "config.toml"
			var conf ss.Config
			if err := ss.ParseConfig(path, &conf); err != nil {
				return err
			}

			srv := new(pnode)
			if err := srv.init(&conf); err != nil {
				return err
			}

			return srv.serve()
		},
	}

	app.Run(os.Args)
}
