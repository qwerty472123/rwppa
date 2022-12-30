// Copyright (C) 2020  CoolSpring8

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Rwppa is a tool that exposes an HTTP proxy service intercepting requests to pass through ZJU RVPN web portal.
// In other words, on receiving requests, they will be sent to rvpn.zju.edu.cn and corresponding results will be passed back to the browser,
// or any other HTTP-proxy-capable requesters, like clients that only utilize HTTP protocol.

// In short, users are given the ability to access ZJU intranet sites,
// with a ZJU internet service account required, and via ZJU RVPN web portal (view rvpn.zju.edu.cn on phones to see).
// Hopefully it can replace the role of Sangfor EasyConnect, to a certain extent.

// Only HTTP(s) protocol is supported. WebSocket, FTP, SSH and any other ones are not.

// This program is powered by an MITM-like procedure, so use it at your own risk.

// Most of proxy functionalities are imported from https://github.com/elazarl/goproxy/ , An HTTP proxy library for Go.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/coolspring8/rwppa/internal/proxy"
	"github.com/coolspring8/rwppa/pkg/rvpn"
	"os"
)

type StartupConf struct {
	// FilterId is the filter id in WebVPN(some filter will change the content, others won't)
	// 1 - HTML, 2 - CSS, 3 - JS, 4 - VBS
	FilterId uint64 `json:"filterId"`
	// VpnURL is the url which provided ancient Sangfor WebVPN
	// Examples: https://rvpn.zju.edu.cn
	VpnURL string `json:"vpnURL"`
	// Username is WebVPN network service account username.
	Username string `json:"username"`
	// Password is WebVPN network service account password.
	Password string `json:"password"`
	// ListenAddr is where proxy to listen.
	ListenAddr string `json:"listenAddr"`
}

func (conf *StartupConf) Run() {
	twfidGetter := func() string {
		w := rvpn.WebPortal{VpnURL: conf.VpnURL, Username: conf.Username, Password: conf.Password}
		twfid, err := w.DoLogIn()
		if err != nil {
			panic(err)
		}
		fmt.Println("Current TWFID:", *twfid)
		return *twfid
	}
	vpnAccessURLPrefix := conf.VpnURL + "/web/" + fmt.Sprintf("%d", conf.FilterId) + "/"
	proxy.StartProxyServer(conf.ListenAddr, twfidGetter, vpnAccessURLPrefix)
}

func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Printf("Usage: %s [conf]\n", os.Args[0])
		return
	}
	fn := args[0]
	buf, err := os.ReadFile(fn)
	if err != nil {
		panic(err)
	}
	var conf StartupConf
	err = json.Unmarshal(buf, &conf)
	if err != nil {
		panic(err)
	}
	conf.Run()
}
