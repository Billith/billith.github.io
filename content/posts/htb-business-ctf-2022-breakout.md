---
title: "HTB Business CTF 2022 Breakout"
date: 2022-07-19T22:23:37+02:00
showDate: true
draft: false
tags: ["ctf","re","htb"]
---

Breakout
============
##### [re, 300 points]

> ```The CCSS suffered a ransomware attack that compromised the Unique Digital Medical File (EDUS) and the National Prescriptions System for the public pharmacies. They've reported that their infrastructure has been compromised, and they cannot regain access. The APT left their implant interface exposed, though, and you'll need to break into it and find out how it works. NOTE: This challenge is intended to be solved before 'Breakin'.```

The task started with an access to HTTP server running in the docker container. The server provided access to whole filesystem of the container.

![image](/images/posts/breakout-1.png)

Quick recon shown that it was some custom HTTP server, so since it was re challenge I did not poke too much with the filesystem, I just quickly downloaded the `bkd` binary.

![image](/images/posts/breakout-2.png)

![image](/images/posts/breakout-3.png)

I throwed downloaded binary into IDA and started reversing. This custom server was a HTTP server written in a C++ using boost library.

![image](/images/posts/breakout-4.png)

After checking out each defined endpoint I found the flag string.

![image](/images/posts/breakout-5.png)

```
HTB{th3_pr0c_f5_15_4_p53ud0_f1l35y5t3m_wh1ch_pr0v1d35_4n_1nt3rf4c3.....}
```
