# shadysocks

[![Build Status](https://travis-ci.org/en/shadysocks.svg?branch=master)](https://travis-ci.org/en/shadysocks)

```
+------+  SOCKS5   +-------+  shadowsocks   +-------+  TCP/UDP   +-----+
| user | --------> | rnode | -------------> | pnode | ---------> | dst |
+------+           +-------+       W        +-------+            +-----+
```

# 安装
1. 确认$GOPATH有效
2. go get -v github.com/en/shadysocks/cmd/{pnode,rnode}
3. 测试（可选）
  - 安装dante-client 1.2.x+和nmap-ncat后，拷贝shadysocks/tests/socksify/socks.conf到/etc下
  - 进入$GOPATH/src/github.com/en/shadysocks下运行./tests/test.sh测试
4. rnode运行在本地，pnode运行在远程服务器，并确认两者运行目录下有config.toml
5. 修改rnode的config.toml， pnode = "远程服务器地址:8388"
6. 修改pnode的config.toml， pnode = "0.0.0.0:8388"， 监听本地8388端口
7. chrome安装扩展SwitchyOmega， proxy server设置为rnode监听地址，默认为127.0.0.1:1081，协议为SOCKS5

# 特性
* 支持SOCKS5 CONNECT
* 支持SOCKS5 UDP ASSOCIATE
* 支持OTA
* 兼容原版ss
