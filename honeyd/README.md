# Honeyd
http://www.honeyd.org/index.php  
http://www.citi.umich.edu/u/provos/papers/honeyd-dfn/index.html  
Горшочек с медом - позволяет имитировать сети, хосты, операционные системы, службы и проксирование.  

Depends on:  
> adduser (>= 3.52)  
> libc6 (>= 2.15)  
> libdumbnet1 (>= 1.8)  
> libevent-1.4-2 (>= 1.4.14b-stable)  
> libpcap0.8 (>= 0.9.8)  
> libreadline6 (>= 6.0)  
> zlib1g (>= 1:1.1.4)  

## Сборка  
```bash
./configure
make
make install
```

## Установка deb пакета
```bash
dpkg -i honeyd_1.5c_amd64.deb
```

## Запуск
> NAME  
honeyd − Honeypot Daemon  
> SYNOPSIS  
```bash  
honeyd [ −dP] [ −l logfile] [ −p fingerprints] [ −x xprobe] [ −a assoc] [ −f file]
	[ −i interface] [ −V|--version] [ −h|--help] [ −-include-dir] [ −i interface] [net ...]
```
> DESCRIPTION  

Honeyd creates virtual hosts for IP addresses matching the specified net. The daemon simulates the networking stack of the configured hosts and can simulate any TCP and UDP service. ICMP is fully supported, too. By default, all UDP ports are closed and honeyd will generate an ICMP unreachable port message if the configured personality permits that.  
Honeyd enables a single host to claim unused addresses on a LAN for network simulation. The net argument may contain multiple addresses and network ranges.  
In order for honeyd to receive network traffic for IP addresses that it should simulate, it is necessary to either explicitly route traffic to it, use proxy arp or run arpd(8) for unassigned IP addresses on a shared network.  
honeyd exits on an interrupt or termination signal.  

> The options are as follows:  

| −d | Do not daemonize, and enable verbose debugging messages. |
| −P |On some operating systems, it is not possible to get event notifications for pcap via select(2). In that case, honeyd needs to run in polling mode. This flag enables polling. |
|−l logfile|Log packets and connections to the logfile specified by logfile.|
|−p fingerprints|Read nmap style fingerprints. The names defined after the token are stored as personalities. The personalities can be used in the configuration file to modify the behaviour of the simulated TCP stack.|
|−x xprobe|Read xprobe style fingerprints. This file determines how honeyd reacts to ICMP fingerprinting tools.|
|−a assoc|Read the file that associates nmap style fingerprints with xprobe style fingerprints.|
|−f file|Read the configuration in file. It is possible to create host templates with the configuration file that specify which servers should run and which scripts should be started to simulate them. honeyd will reread the configuration file when sent a SIGHUP signal.|
|−i interface|Listen on interface. It is possible to specify multiple interfaces.|
|−V (--version)|Print version information and exit.|
|−h (--help)|Print summary of command line options and exit.|
|−-include-dir|For plugin development. Reports the directory in which honeyd stores its header files.|
|net|The IP address or network (specified in CIDR notation) or IP address ranges to claim (e.g. '10.0.0.3', '10.0.0.0/16' or '10.0.0.5-10.0.0.15'). If unspecified, honeyd will attempt to claim any IP address it sees traffic for.|

Минимальная конфигурация для запуска:  
```bash
honeyd -d -p nmap.prints -f <config-file> <NET-address>
```

## Конфигурирование
```bash
config = creation | addition | binding | set | annotate | route [config] | option
creation = "create" template-name | "create" "default" | "dynamic" template-name
addition = "add" template-name proto "port" port-number action | "add" template-name "subsystem" cmd-string ["shared"] |
	"add" template-name "use" template-name "if" condition
binding = "bind" ip-address template-name | "bind" condition ip-address template-name |
	"bind" ip-address "to" interface-name | "clone" template-name template-name
set = "set" template-name "default" proto "action" action | "set" template-name "personality" personality-name |
	"set" template-name "personality" "random" | "set" template-name "uptime" seconds | "set" template-name "droprate" "in" percent |
	"set" template-name "uid" number ["gid" number] | "set" ip-address "uptime" seconds
annotate = "annotate" personality-name [no] finscan | "annotate" personality-name "fragment" ("drop" | "old" | "new")
route = "route" "entry" ipaddr | "route" "entry" ipaddr "network" ipnetwork | "route" ipaddr "link" ipnetwork |
	"route" ipaddr "unreach" ipnetwork | "route" ipaddr "add" "net" ipnetwork "tunnel" ipaddr(src) ipaddr(dst) |
	"route" ipaddr "add" "net" ipnetwork ipaddr
	["latency" number"ms"] ["loss" percent] ["bandwidth" number["Mbps"|"Kbps"] ["drop" "between" number "ms" "-" number "ms" ]
proto = "tcp" | "udp" | "icmp"
action = ["tarpit"] ("block" | "open" | "reset" | cmd-string | "internal" cmd-string "proxy" ipaddr":"port )
condition = "source os =" cmd-string | "source ip =" ipaddr | "source ip =" ipnetwork | "time " timecondition
timecondition = "between" time "-" time
option = "option" plugin option value
```
#### ROUTING TOPOLOGY
Создание полной топологии сети, включая и маршрутизацию.  
Для имметация сети необходимо добавить маршрутизатор:  
```bash
route entry <IP-address> network <NET-address>
```
Подключение сети к маршрутизатору:  
```bash
route <IP-address> link <NET-address>
```
Добавление новой сети к маршрутизатору:  
```bash
route <IP-address> add net <NET-address-new> <IP-address-new>
```
Подключение к внешней сети выполняется командой:  
```bash
bind <IP-address> to <interface-name>
```
Example:  
```bash
route entry 10.0.0.100 network 10.0.0.0/16
route 10.0.0.100 link 10.0.1.0/24
route 10.0.0.100 add net 10.1.0.0/16 10.0.1.100
route 10.0.1.100 link 10.1.0.0/16
bind 10.1.1.53 to eth0
```
#### VIRTUAL HOSTS
Добавить виртуальную машину:  
```bash
create <VM-name>
```
Добавить виртуальной машине соответсвующие отпечатки:  
```bash
set <VM-name> personality "<NMAP-name>"
```
Открыть порты в виртуальной машине:  
```bash
add <VM-name> <protocol> port <port-number> <action>
set <VM-name> default <protocol> action reset
```
Скомутировать виртуальную машину:  
```bash
bind <IP-address> <OS-name>
```
Example-1:  
```bash
create windows
set windows personality "Windows NT 4.0 Server SP5-SP6"
add windows tcp port 80 "perl scripts/iis-0.95/iisemul8.pl"
add windows tcp port 139 open
add windows tcp port 137 open
add windows udp port 137 open
add windows udp port 135 open
set windows default tcp action reset
set windows default udp action reset
bind 10.0.1.51 windows
```
Example-2:  
```bash
create OpenBSD
set OpenBSD personality "OpenBSD 2.6-2.7"
add OpenBSD tcp port 80 "sh scripts/web.sh"
add OpenBSD tcp port 22 "sh scripts/test.sh $ipsrc $dport"
set OpenBSD default tcp action reset
bind 10.0.1.52 OpenBSD
```

#### SCRIPTING WITH PYTHON  
```python
import honeyd
import sys

def honeyd_init(data):
	mydata = {}
	honeyd.read_selector(honeyd.EVENT_ON)
	return mydata

def honeyd_readdata(mydata, data):
	honeyd.read_selector(honeyd.EVENT_ON)
	honeyd.write_selector(honeyd.EVENT_ON)
	mydata["write"] = data
	return 0

def honeyd_writedata(mydata):
	data = mydata["write"]
	del mydata["write"]
	return data

def honeyd_end(mydata):
	del mydata
	return 0
```


## Дополнительные скрипты  
http://www.honeyd.org/contrib.php  
http://www.citi.umich.edu/u/provos/honeyd/msblast.html
