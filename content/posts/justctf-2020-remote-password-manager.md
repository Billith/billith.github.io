---
title: "justCTF 2020 Remote Password Manager"
date: 2021-02-02T17:30:42+01:00
showDate: true
draft: false
tags: ["ctf","fore","forensic","volatility","memdump","rdp","gimp"]
---

Remote Password Manager
============
##### [fore, 347 points, 12 solves]
> ```TLDR; The challenge consists of a single vmem file (VM memory dump). After some analysis, one of the things that stand out was that the `mstsc.exe` process was running. After a little bit of poking around, the flag could be found in one of the images preserved in the process memory.```

![image](/images/posts/remote-password-manager-1.png)

The starting point of the challenge is a vmem file. It is a virtual memory file used by various hypervisors to store RAM on VM suspension. The well-known tool for memory analysis, [Volatility](https://github.com/volatilityfoundation/volatility), is able to deal with that type of file, so let's try it. First, we need to identify the system and its version.

![image](/images/posts/remote-password-manager-2.png)

After a couple of minutes, it did return the suggested Windows profile. Many people couldn't find it because of the outdated version of Volatility. Always try updating your tools when something that should work, doesn't. Having a proper profile, now we can try to use various modules to see what we're dealing with. The first thing I usually check is a list of running processes. That can tell a lot about the purpose of the system and point out other interesting places that are worth looking at. This time there wasn't much going on, only standard system processes were running. However, we know that we need to look for "remote" thing so another glance on the process list should shift our attention towards two processes, MS Edge and RDP client (`mstsc.exe`). Looking at the hint, we can safely ignore the browser and focus on the RDP client.

```sh
➜  ~ vol.py -f pub/challenge.vmem --profile Win10x64_18362 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID (...)
------------------ -------------------- ------ ------ (...)
0xffffe00d93088040 System                    4      0 (...)
0xffffe00d930d6080 Registry                136      4 (...)
(...)
0xffffe00d9af0f480 svchost.exe            4044    692 (...)
0xffffe00d9af57080 mstsc.exe              6484   3904 (...)
0xffffe00d9afd2080 svchost.exe            6832    692 (...)
0xffffe00d9b0693c0 WmiApSrv.exe           6928    692 (...)
0xffffe00d9ae87080 audiodg.exe            7792   1944 (...)
0xffffe00d9a24a4c0 MicrosoftEdgeC         8104    904 (...)
0xffffe00d9b6454c0 MicrosoftEdgeC         7636    904 (...)
0xffffe00d9b1c14c0 MicrosoftEdgeC         7532    904 (...)
0xffffe00d9340f080 cmd.exe                7420   2448 (...)
0xffffe00d930d0080 conhost.exe            8024   7420 (...)
➜  ~ 
```

Generally, RDP connections are encrypted, right? But at some point, the transmitted data have to be decrypted and displayed in the client's window. Some of the displayed images might be still present in the process memory despite receiving new screen updates or closing connection. However tools like binwalk or foremost won't find these images since they are just plain bitmaps. The easiest and the most efficient way of looking for bitmaps inside memory dumps is just using Gimp. Gimp allows you to load arbitrary data blob as a bitmap and display it. However, it would be a pain to find a bitmap with unknown width in a 1GB memory dump. So to make it at least slightly easier let's dump the memory of the process we are particularly interested in, `mstsc.exe`.

![image](/images/posts/remote-password-manager-3.png)

Now, when we have smaller dump, let's load it to the Gimp and look for some regions that don't look totally random. First, we have to rename `6484.dmp` to `6468.data`, so Gimp will be able to see it. Then select from the menu `File` -> `Open` -> `Select File Type` -> `Raw image data` and open `6468.data`. Let's start by changing the width to 1080 and height to max visible value, in my case 545.
![image](/images/posts/remote-password-manager-4.png)

The first thing that doesn't look like some garage is some kind of icon (I guess?). But that's not what we are looking for.

![image](/images/posts/remote-password-manager-5.png)

Going further and adjusting width leads us to the flag, which was displayed in the notepad on the remote server. 

![image](/images/posts/remote-password-manager-7.png)

I guess that's not the best way to store your passwords, is it?
