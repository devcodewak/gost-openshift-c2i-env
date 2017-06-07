package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"

	"github.com/ginuerzh/gost"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
)

var (
	options struct {
		ChainNodes, ServeNodes flagStringList
	}
)

func init() {
	var (
		configureFile string
		printVersion  bool
	)

	flag.StringVar(&configureFile, "C", "", "configure file")
	flag.Var(&options.ChainNodes, "F", "forward address, can make a forward chain")
	flag.Var(&options.ServeNodes, "L", "listen address, can listen on multiple ports")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.Parse()

	if err := loadConfigureFile(configureFile); err != nil {
		glog.Fatal(err)
	}

	if glog.V(5) {
		http2.VerboseLogs = true
	}

	//openshift v3 c2i env https://raw.githubusercontent.com/amsokol/openshift-golang-template
	//-L=http2://user:pass@:8080
	strMode := os.Getenv("GS_MODE") //http2 tls wss http ws
	strUser := os.Getenv("GS_USER") //""
	strPass := os.Getenv("GS_PASS") //""
	strHost := os.Getenv("GS_HOST") //""
	strPort := os.Getenv("GS_PORT") //PORT
	if strMode != "" && strPort != "" && len(options.ChainNodes) == 0 {
		strServeNode := strMode + "://" + strUser
		if strPass != "" {
			strServeNode += ":" + strPass + "@"
		}
		strServeNode += strHost + ":" + strPort
		options.ServeNodes = append(options.ServeNodes, strServeNode)
		fmt.Printf("[SVR] %v\n", options.ServeNodes)
	} else if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}

	if printVersion {
		fmt.Fprintf(os.Stderr, "gost %s (%s)\n", gost.Version, runtime.Version())
		return
	}
}

func main() {
	chain := gost.NewProxyChain()
	if err := chain.AddProxyNodeString(options.ChainNodes...); err != nil {
		glog.Fatal(err)
	}
	chain.Init()

	var wg sync.WaitGroup
	for _, ns := range options.ServeNodes {
		serverNode, err := gost.ParseProxyNode(ns)
		if err != nil {
			glog.Fatal(err)
		}

		wg.Add(1)
		go func(node gost.ProxyNode) {
			defer wg.Done()
			certFile, keyFile := node.Get("cert"), node.Get("key")
			if certFile == "" {
				certFile = gost.DefaultCertFile
			}
			if keyFile == "" {
				keyFile = gost.DefaultKeyFile
			}
			cert, err := gost.LoadCertificate(certFile, keyFile)
			if err != nil {
				glog.Fatal(err)
			}
			server := gost.NewProxyServer(node, chain, &tls.Config{Certificates: []tls.Certificate{cert}})
			glog.Fatal(server.Serve())
		}(serverNode)
	}
	wg.Wait()
}

func loadConfigureFile(configureFile string) error {
	if configureFile == "" {
		return nil
	}
	content, err := ioutil.ReadFile(configureFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(content, &options); err != nil {
		return err
	}
	return nil
}

type flagStringList []string

func (this *flagStringList) String() string {
	return fmt.Sprintf("%s", *this)
}
func (this *flagStringList) Set(value string) error {
	*this = append(*this, value)
	return nil
}
