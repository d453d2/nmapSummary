# nmap_summary

Python script that summarises a directory of nmap XML scan outputs and creates a deduped and merged summary and report (HTM,CSV,JSON). 

#### Usage 
##### help
```sh
$ python3 nmap_summary.py -h
usage: nmap_summary.py [-h] [--csv CSV] [--html HTML] [--web-only] [--weak-only] [--json JSON] [-t TARGET] [-p {tcp,udp}] input [input ...]

Advanced Nmap result summarizer

positional arguments:
  input                 One or more Nmap XML files or globs

options:
  -h, --help            show this help message and exit
  --csv CSV             Write CSV output
  --html HTML           Write HTML report
  --web-only
  --weak-only
  --json JSON           Write JSON output
  -t, --target TARGET   Filter output for specific host(s) (comma-separated)
  -p, --protocol {tcp,udp}
                        Filter output by protocol
```

#### Examples 
##### Filtering per target IP, and HTML report.
```sh
$ python3 nmap_summary.py -t 127.0.0.1 --html report_127.0.0.1.html ~/nmap/*.xml
127.0.0.1(localhost) TCP:1,2,3,4,5,6,7
127.0.0.1(localhost) UDP:1,2,3,4,5,6,7
[+] Interactive HTML report written to report_127.0.0.1.html
```
##### Filter by target IP and just open TCP ports, with HTML report:
```sh
$ python3 nmap_summary.py -t 127.0.0.1 -p tcp --html report_127.0.0.1.html ~/nmap/*.xml
127.0.0.1(localhost) TCP:1,2,3,4,5,6,7
[+] Interactive HTML report written to report_127.0.0.1.html
```
##### Filter by target IP and just open TCP ports, good for using in another conjunction with another tool:
```sh
$ python3 nmap_summary.py -t 127.0.0.1 -p tcp --web-only ~/nmap/*.xml
127.0.0.1(localhost) TCP:1,4,7
```
##### Complete summary of all scans with dynamic HTML filtering report
```sh
$ python3 nmap_summary.py --html report_all.html ~/nmap/*.xml

[+] XML files processed: 5
[+] Hosts found: 3

Host: 127.0.0.1(localhost)
  TCP Open Ports: 1,2,3,4,5,6,7,8,9
  UDP Open Ports: 2,3,4,5,6

Host: 192.168.1.2
  TCP Open Ports: 1,3,5,6,7,8
  UDP Open Ports: none

Host: 192.168.1.3
  TCP Open Ports: none
  UDP Open Ports: none

[+] Interactive HTML report written to report_all.html
```
