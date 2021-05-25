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

### Challenge:

Here we are given a binary and the source for the binary.

[vuln binary](/assets/images/pwntraining3/ret2libc) and 
[vuln c code](/assets/images/pwntraining3/ret2libc.c)

### Solution:

#### Mitigations: 

Before going into the exploitation its better to check what mitigations are enabled for a bianry. Mitigations are protections that were included to avoid certain attacks. For example.
```bash
checksec --file ./ret2shellcode
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

