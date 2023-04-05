---
title: "HackTheBox - Eat the Cake!"
date: 2020-03-01T00:37:22+01:00
showDate: true
draft: false
tags: ["htb","re","upx"]
---

Eat the Cake!
===
##### [rev, 641 solvers]

> ```TLDR; Simple re challenge written in C++, which checks every character of the input. Despite used language, it's easily reversible doing only static analysis.```

At the start of the challenge I was given one file called `cake.exe`. Quick `file` check revealed that it's UPX packed binary. To unpack it I used standard tool available in kali repositories:    

```bash
➜  upx -d cake.exe 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     15872 <-      9216   58.06%    win32/pe     cake.exe

Unpacked 1 file.
```

When binary is run, it expects 10 characters long password and then 15 characters long password. Looking at `strings cake.exe` output I saw few interesting strings. One of them was expecially interesting:

```bash
➜  strings cake_1.exe
...
Congratulations! Now go validate your flag!
...
```

So, when I knew where I should start looking, next thing I did was loading binary into Ghidra. I opened **Window -> Defined Strings**, located interesting string once again and looked on a references to that address.

![image](/images/posts/eat-the-cake-1.png)

There is only one reference to that string at address `0x40152d`. Following this reference, I jumped to the code where this string is used and where probably the password is validated. After that I checked references to the function I was currently in. There's only one reference and it's in the entry function. That basiclly mean it's probablly **main** function. Decompiled code shows that both passwords are stored in the same buffer and program asks for the second password, only when the first one isn't 15 characters long. If input satisfies required conditions, program prints `"Congratulations! Now go validate your flag!\n"`, otherwise it prints `"Better luck next time...\n"`. There are actually two flags that determines if the input is correct. The first one is the result of function call and the second one is just a local variable, which is set during execution. To make it more readable I changed function return type and local variable type to bool.

```c
if (((flag1 == false) || (flag2 == false)) || 
  (output = "Congratulations! Now go validate your flag!\n", local_439 == false)) {
    output = "Better luck next time...\n";
}
FUN_00401ba0((int *)cout_exref,output);
```

But let's get back to the beginning of the function. First, program prints some banner and checks input length. After that, first flag is set to the return value of function `FUN_004012f0`:

```c
if (15 < local_424) {
  _Src = local_438[0];
}
strncpy_s(&input,0x400,(char *)_Src,0x400);
local_21 = 0;
flag1 = FUN_004012f0(&input);
```

This function implements checks on some of the characters from provided input. For these checks, it's using two imported function from standard library, `isdigit` and `atoi`. The first one takes an integer as a parameter and checks if it's in a range from 0 to 9. If it is, function return true (non 0), otherwise return false (0). Second function tries to cast string to integer. In case of failure, it returns 0, otherwise it return converted value as a integer.

```c
bool __fastcall check_1(char *input)

{
  int iVar1;
  int iVar2;
  
  iVar1 = isdigit((int)input[6]);
  if (iVar1 != 0) {
    iVar1 = isdigit((int)input[12]);
    if (iVar1 != 0) {
      iVar1 = atoi(input + 6);
      iVar2 = atoi(input + 12);
      if ((((iVar1 == 3) && (iVar2 == 1)) && (input[4] == 't')) && (input[7] == 'p')) {
        return true;
      }
    }
  }
  return false;
}
```

This function return true if a given conditions are meet:
* 7th character is a digit and it equals 3
* 13th character is a digit and equals 1
* 5th character is 't'
* 8th character is 'p'

Based on this, it's possible recover part of the password:

```
----------------------------------------------
|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|
|  |  |  |  | t|  | 3| p|  |  |  |  | 1|  |  |
----------------------------------------------
```

After first checks are passed, there are another smililar checks in the main function. However, in order to make the code more readable, the type of out input buffer has to be changed. Currently it's just `char`, but we know that input is stored in a array of length at most 1024 characters. After redefinition of a type, further checks are pretty easy to read:

```c
  if ((input[3] == 'k') && (input[8] == 'a')) {
    flag2 = local_439;
    if ((input[0] != 'h') || (input[10] != 'a')) goto LAB_004014fd;
    if (((input[5] == 'h') && (input[9] == 'r')) && (input[11] == 'd')) {
      flag2 = true;
      goto LAB_004014fd;
    }
  }
  flag2 = false;
LAB_004014fd:
  if ((input[1] == '@') && (input[14] == 'E')) {
    if ((input[2] == 'c') && (input[13] == '$')) {
      local_439 = true;
    }
  }
  else {
    local_439 = false;
  }
```

To pass these checks, given conditions have to be meet:
* 4th character is 'k'
* 9th character is 'a'
* 1st character is 'h'
* 11th character is 'a'
* 6th character is 'h'
* 10th character is 'r'
* 12th character is 'd'
* 2nd character is '@'
* 15th character is 'E'
* 3rd character is 'c'
* 14th character is '$'

Based on this,  it's possible recover whole password:

```
----------------------------------------------
|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|
| h| @| c| k| t| h| 3| p| a| r| a| d| 1| $| E|
----------------------------------------------
```

Now when we run the program and pass `h@ckth3parad1$E` as input, `Congratulations! Now go validate your flag!` is printed, which means we've got the correct password.
