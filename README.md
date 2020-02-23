# Basic Web Scanner

nmap scan for open ports, find out if they are web servers, then run specific scanners against them

script currently runs:
* Nikto
* Whatweb
* Dirb


## Dependacies

as well as the web scanners listed above, this script relies on the python-nmap package

```
python3 -m pip install python-nmap
```

## Usage
```
python3 basicwebscan.py <ip address or CIDR range> <output directory>
```
