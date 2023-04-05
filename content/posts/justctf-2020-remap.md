---
title: "justCTF 2020 REmap"
date: 2021-02-04T22:21:18+01:00
showDate: true
draft: true
tags: ["ctf","re","python","obfuscation","pyc","cpython"]
---

REmap
============
#### [re, 383 points, 8 solves]
TLDR; In the beginning, we were provided with PE32 file created using pyinstaller. Upon extracting packed Python program you could see that pyc file containing Python bytecode cannot be easily decompiled. In order to decompile, we needed to remap custom opcodes to the standard onces. This could be done using a custom Python interpreter, which we extracted alongside with pyc file. The source code was heavily obfuscated, but after small additions to the code, the flag could be easily revealed.
![image](/images/posts/remap-3.png)

Challenge description says that they fired admin responsible for backups and now they're fucked. The admin prepared program for decrypting backups, but accidentally "forgot" to leave the password required to run it. This password is obviously our precious flag. Binary itself is pretty big, 5.7M, which may raise suspicions that it's not ordinary PE32 file. Upon closer inspection in IDA, we can see several interesting strings in the main function.
![image](/images/posts/remap-1.png)

Quick google research shows that PyInstaller was used to create this binary.
![image](/images/posts/remap-2.png)

There are few PyInstaller extractors, but [this one](https://github.com/extremecoders-re/pyinstxtractor) definitely does the job.
```
PS C:\remap> python .\pyinstxtractor\pyinstxtractor.py .\backup_decryptor.exe
[+] Processing .\backup_decryptor.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 38
[+] Length of package: 5598412 bytes
[+] Found 31 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: backup_decryptor.pyc
[+] Found 222 files in PYZ archive
[+] Successfully extracted pyinstaller archive: .\backup_decryptor.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

So far so good. Let's try to follow advice from the last line of the output above. First, we should install some decompiler, so let's install uncompyle6 (3rd result, while searching for "pyc decompiler"). Now we should be able to see how that password is validated. We should, but we don't. Instead we get wierd ass looking traceback.
```
PS C:\remap> uncompyle6.exe .\backup_decryptor.exe_extracted\backup_decryptor.pyc
# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.8.5 (tags/v3.8.5:580fbb0, Jul 20 2020, 15:43:08) [MSC v.1926 32 bit (Intel)]
# Embedded file name: \\vmware-host\Shared Folders\tasks\re\v2\tasks-files\backup_decryptor.py
Traceback (most recent call last):
(...)
  File "c:\users\user\appdata\local\programs\python\python38-32\lib\site-packages\xdis\opcodes\opcode_37.py", line 121, in format_RAISE_VARARGS
    assert 0 <= argc <= 2
AssertionError
```

PyInstaller extractor showed that binary was created using python 3.8. According to [uncompyle6 README](https://github.com/rocky/python-uncompyle6/) this version should be supported, but for some reason we are getting error. If tools failed let's try do check it manually. We can disassemble pyc bytecode using only standard python modules, but for some reason this produces another traceback.
```
PS C:\remap> python
Python 3.8.5 (tags/v3.8.5:580fbb0, Jul 20 2020, 15:43:08) [MSC v.1926 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import marshal; import dis
>>> dis.dis(marshal.loads(open('.\\backup_decryptor.exe_extracted\\backup_decryptor.pyc','rb').read()[16:]))
  1           0 STORE_GLOBAL             0 (builtins)
        >>    2 STORE_GLOBAL             1 (bi)
              4 IMPORT_NAME              0 (builtins)
Traceback (most recent call last):
(...)
_get_instructions_bytes
    argval, argrepr = _get_name_info(arg, varnames)
  File "C:\Users\user\AppData\Local\Programs\Python\Python38-32\lib\dis.py", line 304, in _get_name_info
    argval = name_list[name_index]
IndexError: tuple index out of range
>>>
```

The disassembled code doesn't make any sense and we see similar keywords like dis, opcodes, instructions. At this point, it should be clear that somebody was messing with opcodes. To be absolutly sure we can try to run this custom interpreter and see how does the opcode map look like. To do so, we need to move `python38.dll` to the python installation directory (backup original one!). However, now when we try to run python, it silently crashes.
```
PS C:\remap> python
PS C:\remap> $?
False
PS C:\remap>
```

That's because of the python's standard library. To make startup faster, python always compile libraries to the pyc files when they the libraries are loaded. These pyc files were compiled using standard opcodes. When we try to load them using our remaped python, it will simply crash. To force recompilation of needed libraries library, we need to remove all the `__pycache__` directories.
```
PS C:\remap> gci -Filter __pycache__ -Recurse | ri -Recurse -Force -Confirm:$false
PS C:\remap> python .\backup_decryptor.exe_extracted\backup_decryptor.pyc
Enter password: asdf
Nope
PS C:\remap>
```

We are able to run our backup decryptor with local installtion of python, but somehow it still shows standard opcodes.
```
PS C:\remap> python
Python 3.8.5 (default, Jan 10 2021, 00:42:12) [MSC v.1916 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import opcode
>>> opcode.opmap
{'POP_TOP': 1, 'ROT_TWO': 2, 'ROT_THREE': 3, 'DUP_TOP': 4, 'DUP_TOP_TWO': 5, 'ROT_FOUR': 6, (...) 'POP_FINALLY': 163}
>>>
```
That's because opcodes numbers are hardcoded in the `opcode` module (`Lib\opcode.py`). To see opcodes used by the custom python, we need to remove or just change the name of `Lib\__pycache__\opcode.cpython-38.pyc` and `Lib\opcode.py` file and then find `opcode.pyc` in the extracted files and move it to the `Lib` directory in the python installtion directory. After all of these setps, we can extract custom opcodes mapping.
```
PS C:\remap> python
Python 3.8.5 (default, Jan 10 2021, 00:42:12) [MSC v.1916 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import opcode;opcode.opmap
{'POP_TOP': 64, 'ROT_TWO': 9, 'ROT_THREE': 71, 'DUP_TOP': 60, 'DUP_TOP_TWO': 54, 'ROT_FOUR': 56, (...) 'POP_FINALLY': 162}
>>>
```

Having all the pieces of the puzzle, now we can load backup decryptor code and change all of the opcodes of disassembled instructions to the standard opcodes. Then we can save restored code to the new pyc file and decompile it, using standard tools like uncompyle6. So let's write the solver!

```python3
original_opcodes = {'POP_TOP': 1, 'ROT_TWO': 2, (...) 'POP_FINALLY': 163}
remapped_opcodes = {'POP_TOP': 64, 'ROT_TWO': 9, (...) 'POP_FINALLY': 162}
remapped_opcodes = {v: k for k,v in remapped_opcodes.items()}

pyc_filepath = sys.argv[1]
pyc_contents = open(pyc_filepath, 'rb').read()[16:]
code_obj = marshal.loads(pyc_contents)
original_code_obj = recursively_convert_opcodes(code_obj, original_opcodes, remapped_opcodes)
```
We start off with declaration of orignal and remapped opcode map, later it will be clear, why we need to swap keys and values in the remapped opcode map. Then, we need to open and read bytecode from pyc file. Here's how compile module generates pyc files.
```python3
def _code_to_timestamp_pyc(code, mtime=0, source_size=0):
    "Produce the data for a timestamp-based pyc."
    data = bytearray(MAGIC_NUMBER)
    data.extend(_pack_uint32(0))
    data.extend(_pack_uint32(mtime))
    data.extend(_pack_uint32(source_size))
    data.extend(marshal.dumps(code))   # we only care about this part
    return 
```
To only get the bytecode, we need to skip first 16 bytes of the file. When we have valid code object loaded, we can start our remapping. But before we start actually chaning opcodes, we need to take care of one problem. Single code object can contain multiple nested code objects like functions, moudle etc. And we need to remap all of them to succesfully decompile whole pyc file. So, for every code object we need to check its `co_consts` atribute, which is a tuple containing the literals used by the bytecode. If 

Opcodes remapping is a well known technique to protect software written in python.

```
PS C:\remap> .\backup_decryptor.exe
Enter password: justCTF{b3773r_r3h1r3_7h15_6uy}

Even tho the password is correct, fuck you, I removed the rest of the code. You shouldn't have fire me.
```

```python3
import sys
import dis
import marshal

from types import CodeType


def convert_opcodes(remapped_code_obj, original_opcodes_dict, remapped_opcodes_dict):
    instructions = {i.offset: i.opcode for i in dis.Bytecode(remapped_code_obj)}
    original_code = b''
    current_offset = 0
    while current_offset < len(remapped_code_obj.co_code):
        if current_offset in instructions:
            opcode_val = instructions[current_offset]
            opcode_name = remapped_opcodes_dict[opcode_val]
            original_opcode_val = original_opcodes_dict[opcode_name]
            original_code += bytes([original_opcode_val])
        else:
            original_code += bytes([remapped_code_obj.co_code[current_offset]])
        current_offset += 1
    return original_code

def recursively_convert_opcodes(remapped_code_obj, original_opcodes_dict, remapped_opcodes_dict):
    original_code = convert_opcodes(remapped_code_obj, original_opcodes_dict, remapped_opcodes_dict)
    original_co_consts = []
    for c in remapped_code_obj.co_consts:
        if type(c) == CodeType:
            new_const = recursively_convert_opcodes(c, original_opcodes_dict, remapped_opcodes_dict)
            original_co_consts.append(new_const)
        else:
            original_co_consts.append(c)

    return CodeType(
        remapped_code_obj.co_argcount,
        remapped_code_obj.co_posonlyargcount,
        remapped_code_obj.co_kwonlyargcount,
        remapped_code_obj.co_nlocals,
        remapped_code_obj.co_stacksize,
        remapped_code_obj.co_flags,
        original_code,
        tuple(original_co_consts),
        remapped_code_obj.co_names,
        remapped_code_obj.co_varnames,
        remapped_code_obj.co_filename,
        remapped_code_obj.co_name,
        remapped_code_obj.co_firstlineno,
        remapped_code_obj.co_lnotab,
        remapped_code_obj.co_freevars,
        remapped_code_obj.co_cellvars,
    )

original_opcodes = {'POP_TOP': 1, 'ROT_TWO': 2, 'ROT_THREE': 3, 'DUP_TOP': 4, 'DUP_TOP_TWO': 5, 'ROT_FOUR': 6, 'NOP': 9, 'UNARY_POSITIVE': 10, 'UNARY_NEGATIVE': 11, 'UNARY_NOT': 12, 'UNARY_INVERT': 15, 'BINARY_MATRIX_MULTIPLY': 16, 'INPLACE_MATRIX_MULTIPLY': 17, 'BINARY_POWER': 19, 'BINARY_MULTIPLY': 20, 'BINARY_MODULO': 22, 'BINARY_ADD': 23, 'BINARY_SUBTRACT': 24, 'BINARY_SUBSCR': 25, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_TRUE_DIVIDE': 27, 'INPLACE_FLOOR_DIVIDE': 28, 'INPLACE_TRUE_DIVIDE': 29, 'GET_AITER': 50, 'GET_ANEXT': 51, 'BEFORE_ASYNC_WITH': 52, 'BEGIN_FINALLY': 53, 'END_ASYNC_FOR': 54, 'INPLACE_ADD': 55, 'INPLACE_SUBTRACT': 56, 'INPLACE_MULTIPLY': 57, 'INPLACE_MODULO': 59, 'STORE_SUBSCR': 60, 'DELETE_SUBSCR': 61, 'BINARY_LSHIFT': 62, 'BINARY_RSHIFT': 63, 'BINARY_AND': 64, 'BINARY_XOR': 65, 'BINARY_OR': 66, 'INPLACE_POWER': 67, 'GET_ITER': 68, 'GET_YIELD_FROM_ITER': 69, 'PRINT_EXPR': 70, 'LOAD_BUILD_CLASS': 71, 'YIELD_FROM': 72, 'GET_AWAITABLE': 73, 'INPLACE_LSHIFT': 75, 'INPLACE_RSHIFT': 76, 'INPLACE_AND': 77, 'INPLACE_XOR': 78, 'INPLACE_OR': 79, 'WITH_CLEANUP_START': 81, 'WITH_CLEANUP_FINISH': 82, 'RETURN_VALUE': 83, 'IMPORT_STAR': 84, 'SETUP_ANNOTATIONS': 85, 'YIELD_VALUE': 86, 'POP_BLOCK': 87, 'END_FINALLY': 88, 'POP_EXCEPT': 89, 'STORE_NAME': 90, 'DELETE_NAME': 91, 'UNPACK_SEQUENCE': 92, 'FOR_ITER': 93, 'UNPACK_EX': 94, 'STORE_ATTR': 95, 'DELETE_ATTR': 96, 'STORE_GLOBAL': 97, 'DELETE_GLOBAL': 98, 'LOAD_CONST': 100, 'LOAD_NAME': 101, 'BUILD_TUPLE': 102, 'BUILD_LIST': 103, 'BUILD_SET': 104, 'BUILD_MAP': 105, 'LOAD_ATTR': 106, 'COMPARE_OP': 107, 'IMPORT_NAME': 108, 'IMPORT_FROM': 109, 'JUMP_FORWARD': 110, 'JUMP_IF_FALSE_OR_POP': 111, 'JUMP_IF_TRUE_OR_POP': 112, 'JUMP_ABSOLUTE': 113, 'POP_JUMP_IF_FALSE': 114, 'POP_JUMP_IF_TRUE': 115, 'LOAD_GLOBAL': 116, 'SETUP_FINALLY': 122, 'LOAD_FAST': 124, 'STORE_FAST': 125, 'DELETE_FAST': 126, 'RAISE_VARARGS': 130, 'CALL_FUNCTION': 131, 'MAKE_FUNCTION': 132, 'BUILD_SLICE': 133, 'LOAD_CLOSURE': 135, 'LOAD_DEREF': 136, 'STORE_DEREF': 137, 'DELETE_DEREF': 138, 'CALL_FUNCTION_KW': 141, 'CALL_FUNCTION_EX': 142, 'SETUP_WITH': 143, 'LIST_APPEND': 145, 'SET_ADD': 146, 'MAP_ADD': 147, 'LOAD_CLASSDEREF': 148, 'EXTENDED_ARG': 144, 'BUILD_LIST_UNPACK': 149, 'BUILD_MAP_UNPACK': 150, 'BUILD_MAP_UNPACK_WITH_CALL': 151, 'BUILD_TUPLE_UNPACK': 152, 'BUILD_SET_UNPACK': 153, 'SETUP_ASYNC_WITH': 154, 'FORMAT_VALUE': 155, 'BUILD_CONST_KEY_MAP': 156, 'BUILD_STRING': 157, 'BUILD_TUPLE_UNPACK_WITH_CALL': 158, 'LOAD_METHOD': 160, 'CALL_METHOD': 161, 'CALL_FINALLY': 162, 'POP_FINALLY': 163}
remapped_opcodes = {'POP_TOP': 64, 'ROT_TWO': 9, 'ROT_THREE': 71, 'DUP_TOP': 60, 'DUP_TOP_TWO': 54, 'ROT_FOUR': 56, 'NOP': 52, 'UNARY_POSITIVE': 26, 'UNARY_NEGATIVE': 78, 'UNARY_NOT': 27, 'UNARY_INVERT': 81, 'BINARY_MATRIX_MULTIPLY': 70, 'INPLACE_MATRIX_MULTIPLY': 88, 'BINARY_POWER': 12, 'BINARY_MULTIPLY': 4, 'BINARY_MODULO': 68, 'BINARY_ADD': 29, 'BINARY_SUBTRACT': 11, 'BINARY_SUBSCR': 17, 'BINARY_FLOOR_DIVIDE': 67, 'BINARY_TRUE_DIVIDE': 84, 'INPLACE_FLOOR_DIVIDE': 86, 'INPLACE_TRUE_DIVIDE': 23, 'GET_AITER': 76, 'GET_ANEXT': 82, 'BEFORE_ASYNC_WITH': 19, 'BEGIN_FINALLY': 10, 'END_ASYNC_FOR': 59, 'INPLACE_ADD': 50, 'INPLACE_SUBTRACT': 65, 'INPLACE_MULTIPLY': 79, 'INPLACE_MODULO': 6, 'STORE_SUBSCR': 3, 'DELETE_SUBSCR': 28, 'BINARY_LSHIFT': 25, 'BINARY_RSHIFT': 16, 'BINARY_AND': 62, 'BINARY_XOR': 85, 'BINARY_OR': 75, 'INPLACE_POWER': 73, 'GET_ITER': 72, 'GET_YIELD_FROM_ITER': 83, 'PRINT_EXPR': 22, 'LOAD_BUILD_CLASS': 2, 'YIELD_FROM': 87, 'GET_AWAITABLE': 5, 'INPLACE_LSHIFT': 1, 'INPLACE_RSHIFT': 53, 'INPLACE_AND': 20, 'INPLACE_XOR': 63, 'INPLACE_OR': 57, 'WITH_CLEANUP_START': 66, 'WITH_CLEANUP_FINISH': 55, 'RETURN_VALUE': 89, 'IMPORT_STAR': 15, 'SETUP_ANNOTATIONS': 24, 'YIELD_VALUE': 61, 'POP_BLOCK': 77, 'END_FINALLY': 51, 'POP_EXCEPT': 69, 'STORE_NAME': 125, 'DELETE_NAME': 136, 'UNPACK_SEQUENCE': 106, 'FOR_ITER': 98, 'UNPACK_EX': 144, 'STORE_ATTR': 126, 'DELETE_ATTR': 95, 'STORE_GLOBAL': 156, 'DELETE_GLOBAL': 110, 'LOAD_CONST': 97, 'LOAD_NAME': 155, 'BUILD_TUPLE': 91, 'BUILD_LIST': 154, 'BUILD_SET': 153, 'BUILD_MAP': 133, 'LOAD_ATTR': 132, 'COMPARE_OP': 115, 'IMPORT_NAME': 108, 'IMPORT_FROM': 94, 'JUMP_FORWARD': 102, 'JUMP_IF_FALSE_OR_POP': 158, 'JUMP_IF_TRUE_OR_POP': 103, 'JUMP_ABSOLUTE': 150, 'POP_JUMP_IF_FALSE': 130, 'POP_JUMP_IF_TRUE': 131, 'LOAD_GLOBAL': 113, 'SETUP_FINALLY': 93, 'LOAD_FAST': 141, 'STORE_FAST': 137, 'DELETE_FAST': 114, 'RAISE_VARARGS': 111, 'CALL_FUNCTION': 122, 'MAKE_FUNCTION': 96, 'BUILD_SLICE': 124, 'LOAD_CLOSURE': 161, 'LOAD_DEREF': 147, 'STORE_DEREF': 142, 'DELETE_DEREF': 112, 'CALL_FUNCTION_KW': 107, 'CALL_FUNCTION_EX': 138, 'SETUP_WITH': 145, 'LIST_APPEND': 116, 'SET_ADD': 151, 'MAP_ADD': 152, 'LOAD_CLASSDEREF': 146, 'EXTENDED_ARG': 109, 'BUILD_LIST_UNPACK': 101, 'BUILD_MAP_UNPACK': 157, 'BUILD_MAP_UNPACK_WITH_CALL': 92, 'BUILD_TUPLE_UNPACK': 148, 'BUILD_SET_UNPACK': 104, 'SETUP_ASYNC_WITH': 160, 'FORMAT_VALUE': 149, 'BUILD_CONST_KEY_MAP': 105, 'BUILD_STRING': 100, 'BUILD_TUPLE_UNPACK_WITH_CALL': 143, 'LOAD_METHOD': 90, 'CALL_METHOD': 135, 'CALL_FINALLY': 163, 'POP_FINALLY': 162}
remapped_opcodes = {v: k for k,v in remapped_opcodes.items()}

pyc_filepath = sys.argv[1]
pyc_contents = open(pyc_filepath, 'rb').read()[16:]
code_obj = marshal.loads(pyc_contents)
original_code_obj = recursively_convert_opcodes(code_obj, original_opcodes, remapped_opcodes)

original_pyc = b''.join([
    b'\x55\x0d\x0d\x0a',                # magic bytes
    b'\x00\x00\x00\x00',                # padding
    b'\x00\x00\x00\x00',                # timestamp
    b'\x00\x00\x00\x00',                # padding
    marshal.dumps(original_code_obj),   # restored code object
])

with open('original.pyc', 'wb') as f:
    f.write(original_pyc)
```