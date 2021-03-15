##### 本软件是一个类似于花生壳一样的动态域名系统，实现了核心的DDNS功能，用户管理采用修改配置文件的方式，没有写用户管理页面，所以只能自己使用；写这个软件的原因是：我本来是使用花生壳的，但花生壳老出问题，所以就自己写了一个使用。使用这个系统你得有一个VPS服务器，还得有一个域名。

##### 系统没有使用数据库来管理用户及ddns子域名，直接读写的文本文件，所以应该支撑不了多少并发用户。好在方便部署。

##### 对了，有人问我这个东西是用来干什么的：就是你在外面想访问你家里的电脑，不知道家里的互联网IP是多少（因为老变），现在就可以用一个固定的域名访问你家里的电脑了，不管家里电脑的互联网IP怎么变都没有关系 。

## 使用方法
### 总流程
1. 去域名服务商处申请一个域名
2. 在域名服务商的域名解析页面加一条NS记录指向你的DDNS服务器(具体步骤见域名服务商处配置专题)
3. 在ddns服务器上配置好配置文件并运行 ddnss
4. 把ddnsc客户端运行于你内网的任何机器上(先配置好配置文件)
5. 好了，现在你可以在任何地方通过你自己定义的三级域名访问你PPPOE拨号的网络了

### 域名服务商处配置
#### DDNS的本质
DDNS服务器的本质是：一个DNS服务器(可以是功能单一的，只实现特定小部分功能的DNS服务器)+一个DDNS所需的DDNS用户及动态IP申报系统
#### 域名需求及申请，要跑ddns需要两个域名（其实只有一个域名也行，原因说起来也麻烦，大家自己想了），
+ 一个域名给DDNS子域名用，假设为aaa.com
>NS记录不支持泛解析，只能对一个二级域名(主机)进行NS重定向，因此提供给外部使用的**DDNS域名是三级域名**

+ 另一个是域名指向DDNS服务器(DNS服务器),假设为dns.com
>之所以需要这个域名是因为NS记录指向的DNS服务器必须以域名的方式提共，而不能以IP的方式提供

#### DDNS域名配置
+ 在域名服务商的域名解析配置中加一条NS记录如：ddns.aaa.com 向指自己的ddns服务器域名或主机，如dns.com或ddns.dns.com

#### DDNS服务器域名配置

根据ddns域名NS记录的配置，在域名服务商的域名解析配置中加一条相应的A记录指向自己DDNS服务器的IP，如：@.dns.com 1.1.1.1或ddns.dns.com 1.1.1.1

**配置已经完成了，下面的说明看不看都没关系**
#### 对NS记录配置的几点说明，ddns域名最短也只能是三级域名
+ 在NS记录配置中@和A记录配置一样，代表域名本身
+ \* 和A记录中不一样，在NS记录中\* 代表的就是\* 本身，没有其实特殊含义
+ 在NS记录配置中如果一个二级域名(主机)被配置了NS记录，那么这个二级域名下的所有三级域名的解析都会被重定向转发到这条NS记录对应的DNS服务器。
+ 配置域名本身的NS记录使用的是@符号，无法泛解析该域名下的所有二级域名，ddns域名最短也只能是三级域名

### 服务端
1. 按user.json文件格式，添加用户及用户对应的域名
2. 运行ddnss程序

### 客户端
1. 按config.json文件格式，根据ddns服务端user.json中分配给你的用户名、密码配置好config.json文件
2. 运行ddnsc程序
