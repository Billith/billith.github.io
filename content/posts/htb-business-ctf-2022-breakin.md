---
title: "HTB Business CTF 2022 Breakin"
date: 2022-07-19T22:32:12+02:00
showDate: true
draft: false
tags: ["ctf","re","htb","python","cpython","bytecode"]
---

Breakin
============
##### [re, 400 points]

> ```Previous state-hacking campaigns from these APT actors indicate that they regularly change cryptographic keys, and we believe this server is being used to coordinate them. If you can discover how the keys are being derived, then we'll be able to decrypt all their past worm communication in the network! NOTE: This challenge is intended to be solved after 'Breakout'.```

From the description of the task I knew that first I should find the place where the encryption key is being shared. I glanced through each endpoint in IDA to find something interesting and I noticed, that the `/secret` endpoint returns the HTML page, which has some references to the other endpoints, I thought good place to start. To access the `/secret` endpoint, the flag from the previous task needs to be passed in the `password` parameter.

![image](/images/posts/breakin-1.png)

![image](/images/posts/breakin-2.png)

After that I reversed each endpoint to figure out what exactly is going on. The "Admin panel" let's you upload the python bytecode, it adds it to the list of programs and let's you execute it straight from the memory. By making a `POST` request to the `/exec` endpoint with a appropriate json, you could upload your program, and by making a `GET` request to the `/exec/<program_name>` you could execute it.

The python bytecode of each program is stored in the global variable `program`, which is a map consisting of a pairs of `strings` and objects of the custom class `Payload`, which is essentially `vector` of `unsigned char`.

![image](/images/posts/breakin-3.png)

From the beginning, there were already three "programs" uploaded, `creds`, `key` and `stats`. The `key` program was what I was looking for, because it returns the current encryption key.

![image](/images/posts/breakin-4.png)

My first thought was to somehow upload my python bytecode and dump the process memory to extract the `key` program bytecode and decompile it. So I started analysing further the function `executePython` from the `execGet` handler.

![image](/images/posts/breakin-5.png)

After reading some cpython documentation I knew that this function loads the python object from the bytecode, imports in to the `payload` module, executes the `main` function and returns the results whether it's a `string` or `bytes`. At this point I needed to figure out how to generate a payload, which would be executed by this function, so I wrote simple code to be able to quickly test the bytecode I've generated.

```cpp
#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "marshal.h"
#include <stdio.h>
#include <vector>


int main() {
	std::vector<unsigned char> bytecode = { <bytecode> };

	printf("%ld\n", bytecode.size());
	
	Py_Initialize();
	PyObject* obj = PyMarshal_ReadObjectFromString((const char*)bytecode.data(), bytecode.size());
	printf("%p\n", obj);
	PyObject* mod = PyImport_ExecCodeModule("payload", obj);
	printf("%p\n", mod);
	PyObject* res = PyObject_CallMethod(mod, "main", NULL);
	printf("%p\n", res);
	PyObject* str = PyObject_Str(res);
	printf("%p\n", str);
	PyObject* bytes = PyUnicode_AsUTF8String(str);
	printf("%p\n", bytes);
	char* output = PyBytes_AsString(bytes);
	printf("output: %s\n", output);
	Py_Finalize();
}
```

And compiled it using `gcc` (btw, it took me a fukcing while to figure out the `gcc` arguments and compile it).

```bash
g++ -fpie $(python3-config --cflags --embed) -o test test.cpp $(python3-config --embed --ldflags)
```

After a little bit of testing and trying things out I figured out how to generate the proper bytecode.

```python
import sys
import pickle
import marshal


code = """
def main():
	import sys
	return dir(sys.modules['payload'])
"""

o = compile(code, 'test', 'exec')
o = marshal.dumps(o)

with open('main.dmp', 'wb') as f:
	f.write(o)

for c in o:
	print(hex(c), end=',')
print()
```

First I tried to locate the `programs` variable using `/proc/self/maps` (adding the base address and the `programs` variable offset) and dump the process memory. I managed to do so and I could find some strings of the program names, however it was really hard to precisely locate the address of the bytecode buffer in the memory, so after a while I dropped this path and I focused on the embedded python interpreter. I started looking at the loaded python modules and I noticed that when I list the attributes of the `payload` before and after execution of `key` program, there are some differences.

Before:
![image](/images/posts/breakin-6.png)

After:
![image](/images/posts/breakin-7.png)

I realized that the `key` program loads additional modules like `binascii`, `hashlib` or `struct` and the state of the interpreter is preserved. That's when I came up with an idea to try to register some sort of hook, which would be executed upon every function call. The hook would try to dump the `payload.main` function bytecode to the file. After some research I found exactly what I was looking for.

```python
import sys
import pickle
import marshal


# https://stackoverflow.com/questions/59088671/hooking-every-function-call-in-python
code = """
def call_tracer(frame, event, arg):
	import marshal
	with open('/dump','wb') as f:
		o = marshal.dumps(frame.f_code)
		f.write(o)
	return None

def main():
	import sys
	sys.settrace(call_tracer)
	return dir(sys.modules['payload'].main)
"""

o = compile(code, 'test', 'exec')
o = marshal.dumps(o)

with open('main.dmp', 'wb') as f:
	f.write(o)

for c in o:
	print(hex(c), end=',')
print()
```

I restarted the container, uploaded generated `main.dmp`, executed it and then executed the `key` program. After that I was able to download the dump.

![image](/images/posts/breakin-8.png)

I quickly decompiled it and there it was, the flag:

![image](/images/posts/breakin-9.png)

```
HTB{d1d_y0u_w4lk_th3_tr33_f0r_m3?}
```
