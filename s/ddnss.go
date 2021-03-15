package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"runtime"

	"errors"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"encoding/json"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type DdnsUser struct {
	Users []struct {
		Username    string   `json:"userName"`
		Password    string   `json:"password"`
		Oldip       string   `json:"oldIP"`
		Domainnames []string `json:"domainNames"`
	} `json:"users"`
}

type JArrsy []gjson.Result

var dmnsFile string = "dmns.json"
var userFile string = "user.json"

//把一个[]gjson.Result转为json字符串
func (ja JArrsy) String() string {
	var str string
	if len(ja) == 0 {
		str = "[]"
		return str
	}
	if len(ja) == 1 {
		str = "[" + ja[0].String() + "]"
		return str
	}
	str = "[" + ja[0].String()
	for i := 1; i < len(ja); i++ {
		str = str + "," + ja[i].String()
	}
	str = str + "]"
	return str
}

//检查ddns客户端传入的用户名和密码是否正确,并返回该用户所属所有ddns域名及上次的IP
func checkUser(fileName string, userName string, password string) ([]gjson.Result, bool, string) {

	jsondata, _ := getStringFromFile(fileName)

	user := gjson.Get(jsondata, "users.#(userName="+userName+")#")
	oldIP := gjson.Get(jsondata, "users.#(userName="+userName+").oldIP").String()
	if !user.Exists() {
		return nil, false, ""
	}

	dmns := gjson.Get(user.String(), "#(password="+password+").domainNames")
	if !dmns.Exists() {
		return nil, false, ""
	}
	fmt.Println(dmns)

	dmnsArray := dmns.Array()

	return dmnsArray, true, oldIP
}

//建立ddns用户服务侦听，并等待客户端呼入
func listenUser(listen *net.TCPListener) {
	for {
		tcpConn, err := listen.AcceptTCP()
		if err != nil {
			fmt.Println("当前协程数量：", runtime.NumGoroutine())
			fmt.Println(err)
		}

		fmt.Println("当前协程数量：", runtime.NumGoroutine())
		go handleUserConn(tcpConn)
	}
}

//建立dns解析服务,侦听dns解析请求，并进行解析
func listenDns(conn *net.UDPConn) {
	for {
		//读客户端消息
		buf := make([]byte, 512)
		n, remoteAddress, _ := conn.ReadFromUDP(buf)
		msg := buf[:n]

		fmt.Printf("十六进制表示raw:")
		for i := 0; i < len(msg); i++ {
			fmt.Printf("%X ", msg[i])
		}

		fmt.Println("\n十进制表示raw:", msg)
		fmt.Println("收到客户端消息：", string(msg), "\n")

		go handleDnsMsg(conn, remoteAddress, msg)
	}
}

//处理一次ddns用户呼入的数据
func handleUserConn(conn *net.TCPConn) {
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	var userStr string
	var userName string
	var password string
	buf := make([]byte, 512)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		userStr = string(buf[:n])
		//TODO 解析用户信息并更新域名IP信息
		//传回的用户信息结构：{"userName":"ausername","password":"pppp"}
		userName = gjson.Get(userStr, "userName").String()
		password = gjson.Get(userStr, "password").String()

		dmns, ok, oldIP := checkUser("user.json", userName, password)
		fmt.Println("dmns:", dmns, "oldip:", oldIP)

		if !ok {
			conn.Write([]byte(`{"ok":"no","info":"wrong userName or password!"}`))
			return
		}

		//取该用户最新的IP地址
		ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
		fmt.Println("newIP:", ip, "oldIP:", oldIP)

		//如果ip没变则不做任何处理
		if oldIP == ip {
			fmt.Println("ip no changed")
			conn.Write([]byte(`{"ok":"yes","info":"ip no changed"}`))
			return
		}
		//更新user.json中的oldIP---------------------------------------
		ddnsUser := &DdnsUser{}
		UsersStrFile, _ := getStringFromFile(userFile)

		json.Unmarshal([]byte(UsersStrFile), ddnsUser)

		index := findUserIndex(ddnsUser, userName)
		if index >= 0 {
			ddnsUser.Users[index].Oldip = ip

			newUserByte, _ := json.Marshal(ddnsUser)
			fmt.Println("ddnsUsers:", string(newUserByte))
			writeToNewFile(userFile, string(newUserByte))
		}
		//--------------------------------------------------------------------

		//在domainNames.json中更新所有dmns列表中的域名为conn对端IP地址
		dmnsStr, _ := getStringFromFile(dmnsFile)

		for i := 0; i < len(dmns); i++ {
			path := strings.Replace(dmns[i].String(), ".", "\\.", -1)
			dmnsStr, _ = sjson.Set(dmnsStr, path, ip)
			fmt.Println("dmns[i]", i, dmns[i].String(), "newDmns", dmnsStr)
		}

		writeToNewFile(dmnsFile, dmnsStr)
		conn.Write([]byte(`{"ok":"yes","info":"ip changed"}`))
		return

	}
}

//进行一次dns解析
func handleDnsMsg(conn *net.UDPConn, udpAddr *net.UDPAddr, dnsMsg []byte) {
	//TODO 解析DNS协议并发送回包给客户端
	var msg dnsmessage.Message
	err := msg.Unpack(dnsMsg)
	//如果收到的数据不是DNS数据丢弃
	if err != nil {
		return
	}

	//生成域名-ip对
	dmnIPs := make(map[string]string)
	fmt.Println("questions len", len(msg.Questions))
	for i := 0; i < len(msg.Questions); i++ {
		name := msg.Questions[i].Name.String()
		//去掉域名最后一个.号
		name = name[:len(name)-1]
		ip, err := findIP(name)
		fmt.Println("name:", name, "ip:", ip)
		if err == nil {
			dmnIPs[name] = ip
		}
	}

	//开始根据 dmnIPs的域名-ip对构造dns回包-------------------------
	for name, ip := range dmnIPs {

		var ans dnsmessage.Resource
		var ipByte [4]byte //ip字节码
		//需要返回的IP地址，要先把string转换成[]byte
		ipslice := strings.Split(ip, ".")
		for i := 0; i < 4; i++ {
			t, err := strconv.Atoi(ipslice[i])
			if err != nil {
				//return
				goto IPERROR //若ip错误，则不再构造该ip的回复包
			}
			ipByte[i] = byte(t)
		}

		ans = dnsmessage.Resource{

			Header: dnsmessage.ResourceHeader{
				//域名最后还要有个. 号
				Name:  mustNewName(name + "."), //answer中写入域名
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},

			Body: &dnsmessage.AResource{A: ipByte}, //在answer中写入ip
		}
		msg.Answers = append(msg.Answers, ans)
		msg.Response = true      //这句不加，nslookup不会显示ip
		msg.Authoritative = true //这句有没有都不影响域名解析
	IPERROR:
	}
	//-----------------------------------------------------------------
	bufw, _ := msg.Pack()
	conn.WriteToUDP(bufw, udpAddr)

}

//根据域名查找该域名对应的ip
func findIP(domainName string) (string, error) {
	names, err := getStringFromFile(dmnsFile)
	if err != nil {
		return "", err
	}

	path := strings.Replace(domainName, ".", "\\.", -1)

	resultIP := gjson.Get(names, path)

	fmt.Println("find ip resultIP:", resultIP.String())

	if resultIP.Exists() {
		return resultIP.String(), nil
	} else {
		return "", errors.New("not find this domainName")
	}
}

func main() {

	//建立用户的TCP侦听-------------------------
	tcpaddr, err := net.ResolveTCPAddr("tcp4", ":5333")
	if err != nil {
		fmt.Println("侦听地址错", tcpaddr, err)
		return
	}
	tcpLister, err := net.ListenTCP("tcp", tcpaddr)
	if err != nil {
		fmt.Println("开始tcp侦听出错", err)
	}
	fmt.Println("ddns用户登录运行于：", "5333")
	go listenUser(tcpLister)
	//-------------------------------------------

	//建立dns服务侦听------------------------------
	udpAddr, err := net.ResolveUDPAddr("udp", ":53")
	if err != nil {
		fmt.Println(err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer udpConn.Close()

	go listenDns(udpConn)
	//-------------------------------------------

	var stop chan int
	stop <- 1
	stop <- 1

}

//从文件读入数据为字符串
func getStringFromFile(fileName string) (string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return "", err
	}
	defer f.Close()
	fd, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println("ioutil 读取文件失败:", err)
		return "", err
	}
	return string(fd), nil
}

//把字符串覆盖写入一个文件
func writeToNewFile(wFileName string, conext string) (n int, err error) {
	var err1 error
	var f *os.File

	if checkFileIsExist(wFileName) { //如果文件存在
		err1 = os.Remove(wFileName)
		if err1 != nil {
			fmt.Println(err1)
			return -1, err1
		}

	}
	f, err1 = os.Create(wFileName) //创建文件
	if err1 != nil {
		fmt.Println(err1)
		return -1, err1
	}

	n, err1 = io.WriteString(f, conext) //写入文件(字符串)
	if err1 != nil {
		fmt.Println(err1)
		return -1, err1
	}
	f.Close()

	return n, err1
}

/**
 * 判断文件是否存在  存在返回 true 不存在返回false
 */
func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

//根据字符串生成一个dnsmessage.Name
func mustNewName(name string) dnsmessage.Name {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		panic(err)
	}
	return n
}

//根据用户名查找该用户在用户数组中的下标。
func findUserIndex(u *DdnsUser, userName string) int {
	fmt.Println(u.Users, userName)
	for i := 0; i < len(u.Users); i++ {
		if u.Users[i].Username == userName {
			return i
		}
	}
	return -1
}
