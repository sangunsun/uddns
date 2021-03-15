package main

import (
	"crypto/rc4"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"time"

	"github.com/buger/jsonparser"
)

type Rc4 struct {
	C *rc4.Cipher
}

var ffilename = flag.String("f", "config.json", "配置文件名")

var fileName string
var serverIP string
var serverPort string
var userName string
var pwd string

func init() {

	flag.Parse()
	fileName = *ffilename
}

func main() {
	f, err := os.Open(fileName)
	if err != nil {
		fmt.Println("打开配置文件失败")
		return
	}
	var jsondata []byte
	var buf = make([]byte, 1)
	for n, err := f.Read(buf); err == nil && n > 0; n, err = f.Read(buf) {
		jsondata = append(jsondata, buf[0])
	}

	serverIP, err = jsonparser.GetString(jsondata, "serverIP")
	if err != nil {
		fmt.Println("配置文件中无服务器ip", serverIP, err)
		return
	}
	serverPort, err = jsonparser.GetString(jsondata, "serverPort")
	if err != nil {
		fmt.Println("配置文件中无服务端口号", serverPort, err)
		return
	}

	userName, err = jsonparser.GetString(jsondata, "userName")
	if err != nil {
		fmt.Println("配置文件中无用户名", err)
		return
	}

	pwd, err = jsonparser.GetString(jsondata, "password")
	if err != nil {
		fmt.Println("配置文件中无密码", err)
		return
	}

	if serverIP == "" || serverPort == "" {
		fmt.Println("请输入服务器IP及端口号")
		return
	}

	ticker := time.NewTicker(time.Second * 10)
	for {
		select {
		case <-ticker.C:
			sendIPToServer(serverIP, serverPort, userName, pwd)
		}
	}

}

func sendIPToServer(serverIP string, serverPort string, userName string, pwd string) {

	address := serverIP + ":" + serverPort
	fmt.Println("服务器地址address:", address)
	tcpaddr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		log.Println("tcp地址错误", address, err)
		return
	}
	fmt.Println("tcpaddr:", tcpaddr)
	server, err := net.DialTCP("tcp", nil, tcpaddr)
	if err != nil {
		log.Println("拨号服务器失败", err)
		return
	}
	fmt.Println("tcpConn:", server, server.RemoteAddr())
	defer server.Close()
	msgStr := `{"userName":"` + userName + `","password":"` + pwd + `"}`
	server.Write([]byte(msgStr))
	buf := make([]byte, 1024)
	n, _ := server.Read(buf)
	fmt.Println(string(buf[:n]))
}
