# Работа с сетевым трафиком  
 
 В данной директории распологиается описание генерации сетевого трафика, а также примеры сетевого трафика атак и разных протоколов  

# Информация о Программах и библиотеках для работы с pcap файлами  

|Имя|Тип|Описание|Ссылка|
| ------------ | ------------ | ------------ | ------------ |
|tcpreplay|утилита|Воспроизведение pcap-файла|https://tcpreplay.appneta.com/|
|Captcp|утилита|Статистика по pcap-файлу|http://research.protocollabs.com/captcp/tut-tcp-througput-analysis-with-captcp.html|
|pcapquiz.py|Python Script|Статистика по pcap-файлу|https://github.com/mirthofthewicked/pcapquiz|
|httpdump|утилита|Захват сетевого трафика, аналог tcpdump|https://github.com/hsiafan/httpdump|
|pcap-parsing.py|Python Script|Extracting Data from pcap files|https://github.com/Abradat/pcap-parsing|
|json2pcap.py|Python Script|Convert json-file to pcap|https://www.h21lab.com/tools/json-to-pcap|
|httpreplay.py|Python Script|Replay HTTP requests from previously captured pcap files|https://github.com/zeha/httpreplay|
|pcap2html.py|Python Script|Convert pcap-file to html|https://github.com/adriangranados/pcap2html|
|Pcap Processor|Python Script|Convert pcap-file to console, kafka, http, csv, grpc|https://github.com/slgobinath/pcap-processor|
|output_summary.py|Python Script|Take in one file and summarize the output to the screen|https://github.com/9b/pcap_tools|
|pcap_summary.py|Python Script|Take in one file or a directory of PCAP files and summarize them in files|https://github.com/9b/pcap_tools|
|json_summary.py|Python Script|Take in a single file and print out a JSON object of all the summary data - meant to show output|https://github.com/9b/pcap_tools|
|pcrappyfuzzer.py|Python Script|A very simple mash-up of Scapy + radamsa to extract data from a PCAP file and perform quick 'n dirty fuzzing ad infinitum|https://github.com/blazeinfosec/pcrappyfuzzer|
|PCAP-Generation-Tools|Python Script|Генератор pcap-трафика|https://github.com/andrewg-felinemenace/PCAP-Generation-Tools|
|pcapedit|Python Script|Редактировать pcap-файл|https://github.com/7h3rAm/pcapedit|
|PyPCAPKit|Python Script|Python multi-engine PCAP analysis kit|https://github.com/JarryShaw/PyPCAPKit|
|pcap_reassembler.py|Python Script|pcap-reassembler is a tool which helps analyzing application layer protocol data without having to inspect segmented transport level payloads|https://github.com/FredrikAppelros/pcap-reassembler|
|kamene|Python lib|Network packet and pcap file rafting/sniffing/manipulation/visualization security tool. Save to pcap-file|https://github.com/phaethon/kamene|
|websnort|Web service|Web service for analysing pcap files with intrusion detection systems such as snort and suricata|https://github.com/shendo/websnort|
|pcap-to-txt.py|Python Script|convert binary pcap file to text files|https://github.com/hbhzwj/pcap-converter|
|pcap-to-flow.py|Python Script|convert pcap file to netflows|https://github.com/hbhzwj/pcap-converter|
|PcapXray|Утилита|A Network Forensics Tool - To visualize a Packet Capture offline as a Network Diagram including device identification, highlight important communication and file extraction|https://github.com/Srinivas11789/PcapXray|
|pcapdb|Утилита|A Distributed, Search-Optimized Full Packet Capture System|https://github.com/dirtbags/pcapdb|
|pcap2curl|Python Script|Read a packet capture, extract HTTP requests and turn them into cURL commands for replay|https://github.com/jullrich/pcap2curl|
|Pcapy|Python lib|Pcapy is a Python extension module that enables software written in Python to access the routines from the pcap packet capture library|https://github.com/helpsystems/pcapy|
|pcap-analyzer|Web service|Web PCAP Storage and Analytic Tool|https://github.com/le4f/pcap-analyzer|
|Python scapy pcap|Python Script|example|https://medium.com/@vworri/extracting-the-payload-from-a-pcap-file-using-python-d938d7622d71|
|trace files with scapy|Python Script|example|https://thepacketgeek.com/importing-packets-from-trace-files/|
|ScapyTrafficGenerator|Python lib|Scapy Traffic Generator|https://pypi.org/project/ScapyTrafficGenerator/|
|Snorpy|Web service|Snorpy a Web Base Tool to Build Snort/Suricata Rules|https://isc.sans.edu/forums/diary/Snorpy+a+Web+Base+Tool+to+Build+SnortSuricata+Rules/24522/|


# Пример использования утилит  

### scapy  
```python
from scapy.all import *
from scapy.utils import rdpcap

file_in = 'example-in.pcap'
file_out = 'example-out.pcap'
pkts = rdpcap(file_in)
for pkt in pkts:
	pkt['IP'].ttl = ''
wrpcap(file_out, pkts, append=False)
```

### tcpwrite  
Редактирование pcap-файла:  
- Обновление checksums в сетевых пакетах  
```bash
tcpwrite --fixcsum --infile=example-in.pcap --outfile=example-out.pcap
```
- Обновление IP-адреса  
```bash
tcprewrite --srcipmap=<IP/NET-src-adresss>:<IP-src-address-new> --dstipmap=<IP/NET-dst-adresss>:<IP-dst-address-new> --infile=example-in.pcap --outfile=example-out.pcap
```
- Обновление MAC-адреса  
```bash
tcprewrite --enet-smac=<MAC-src-address> --enet-dmac=<MAC-dst-address> --infile=example-in.pcap --outfile=example-out.pcap
```
- Пример использования с заменой IP/MAC-адреса и пересчета checksums в сетевых пакетах
```bash
tcprewrite --srcipmap=0.0.0.0/0:192.168.1.1 --enet-smac=00:50:DA:82:9A:01 --dstipmap=0.0.0.0/0:192.168.1.2 --enet-dmac=00:50:DA:82:9A:02 --fixcsum ---infile=example-in.pcap --outfile=example-out.pcap
```
