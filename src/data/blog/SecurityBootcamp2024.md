---
title: "Security Bootcamp 2024: IDA, Votatility, ScyllaHide and how to restore a system encrypted by malware."
description: "Security Bootcamp 2024"
pubDate: 2025-11-5
category: "intro"
draft: false
---

This was written for a challenge in [Security Bootcamp 2024](http://securitybootcamp.org.vn/) in Vietnam. Although it is a competition, the challenge represented a realistic scenario in which ransomware attacks a corporation. We were given only a dump of an affected system whose files had been encrypted by malware. The goal was to decrypt the given file, team06.pdf.sbc.0yk (one of the files that had been encrypted), and retrieve the original content.

The sample files can be downloaded at: https://gdrives.ghtk.co/s/3SaEAwcHJn4WLBR 

We start with listing all processes running and find the SkypeApp.exe from the system by running `vol`:

```powershell
PS C:\1day\malware-analysis> vol -f .\WE-ARE-HOOMAN-20240927-151339.dmp windows.pslist.PsList | findstr "SkypeApp.exe"
5520ress728100.0SkypeApp.exe    0xc503b4ddc080in52hed   -       1       False   2024-09-27 15:11:21.000000 UTC  N/A     Disabled
7008    3932    SkypeApp.exe    0xc503b86c8080  1       -       1       False   2024-09-27 15:13:33.000000 UTC  N/A     Disabled
```

The PID is 7008. Dump the files to get the malware.

```powershell
PS C:\1day\malware-analysis> vol -f .\WE-ARE-HOOMAN-20240927-151339.dmp windows.dumpfiles.DumpFiles --pid 7008
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

ImageSectionObject      0xc503b7caf1f0  KernelBase.dll  file.0xc503b7caf1f0.0xc503b4095590.ImageSectionObject.KernelBase.dll.img
ImageSectionObject      0xc503b83e0460  cryptsp.dll     file.0xc503b83e0460.0xc503b7c6cd30.ImageSectionObject.cryptsp.dll.img
DataSectionObject       0xc503b76bf960  SkypeApp.exe    file.0xc503b76bf960.0xc503b710caf0.DataSectionObject.SkypeApp.exe.dat
ImageSectionObject      0xc503b76bf960  SkypeApp.exe    file.0xc503b76bf960.0xc503b8029d00.ImageSectionObject.SkypeApp.exe.img
ImageSectionObject      0xc503b8b6c6c0  apphelp.dll     file.0xc503b8b6c6c0.0xc503b8b62010.ImageSectionObject.apphelp.dll.img
ImageSectionObject      0xc503b9450200  rsaenh.dll      file.0xc503b9450200.0xc503b83d2a20.ImageSectionObject.rsaenh.dll.img
ImageSectionObject      0xc503b84d7830  sspicli.dll     file.0xc503b84d7830.0xc503b837ccc0.ImageSectionObject.sspicli.dll.img
ImageSectionObject      0xc503b83e02d0  cryptbase.dll   file.0xc503b83e02d0.0xc503b4674050.ImageSectionObject.cryptbase.dll.img
ImageSectionObject      0xc503b7cafe70  msvcp_win.dll   file.0xc503b7cafe70.0xc503b4095050.ImageSectionObject.msvcp_win.dll.img
ImageSectionObject      0xc503b7cae570  bcrypt.dll      file.0xc503b7cae570.0xc503b7c6d550.ImageSectionObject.bcrypt.dll.img
ImageSectionObject      0xc503b7caf9c0  ucrtbase.dll    file.0xc503b7caf9c0.0xc503b7c8ed80.ImageSectionObject.ucrtbase.dll.img
ImageSectionObject      0xc503b7cac3e0  kernel32.dll    file.0xc503b7cac3e0.0xc503b7c8e010.ImageSectionObject.kernel32.dll.img
ImageSectionObject      0xc503b7caea20  advapi32.dll    file.0xc503b7caea20.0xc503b7c802b0.ImageSectionObject.advapi32.dll.img
ImageSectionObject      0xc503b7caebb0  gdi32full.dll   file.0xc503b7caebb0.0xc503b7c80010.ImageSectionObject.gdi32full.dll.img
ImageSectionObject      0xc503b7cae250  win32u.dll      file.0xc503b7cae250.0xc503b460a7a0.ImageSectionObject.win32u.dll.img
ImageSectionObject      0xc503b7caf510  bcryptprimitives.dll    file.0xc503b7caf510.0xc503b460aa00.ImageSectionObject.bcryptprimitives.dll.img
ImageSectionObject      0xc503b7cae890  rpcrt4.dll      file.0xc503b7cae890.0xc503b7c6b010.ImageSectionObject.rpcrt4.dll.img
ImageSectionObject      0xc503b7cad1f0  msvcrt.dll      file.0xc503b7cad1f0.0xc503b460b010.ImageSectionObject.msvcrt.dll.img
ImageSectionObject      0xc503b7caca20  gdi32.dll       file.0xc503b7caca20.0xc503b7c6f010.ImageSectionObject.gdi32.dll.img
ImageSectionObject      0xc503b7cad9c0  user32.dll      file.0xc503b7cad9c0.0xc503b7c6e2b0.ImageSectionObject.user32.dll.img
ImageSectionObject      0xc503b7cac570  sechost.dll     file.0xc503b7cac570.0xc503b7c8e2b0.ImageSectionObject.sechost.dll.img
ImageSectionObject      0xc503b4cef380  ntdll.dll       file.0xc503b4cef380.0xc503b4c67050.ImageSectionObject.ntdll.dll.img
ImageSectionObject      0xc503b7cfd890  imm32.dll       file.0xc503b7cfd890.0xc503b7c6f550.ImageSectionObject.imm32.dll.img
```

Rename `file.0xc503b76bf960.0xc503b8029d00.ImageSectionObject.SkypeApp.exe.img` to `skypeapp.exe` for easier work. I'm using IDA 7.5 to analyze this since the malware has some anti-debug features built in. With IDA 7.5, [ScyllaHide plugin for IDA 7.5](https://github.com/notify-bibi/ScyllaHide-IDA7.5) is available which bypasses the anti-debug features of the malware. I cannot work with x64dbg since I feel like I work better with pseudocode instead of just assembly.



The malware was written in C++, which I have never done reverse engineering against, so I look to certain plugin for easier reverse engineering:

* [IDA Signsrch](https://github.com/nihilus/IDA_Signsrch): On-the-fly signature matching and automatic labeling of known compression, crypto, multimedia and anti-debug routines.
* [Findcrypt: ](https://github.com/polymorf/findcrypt-yara)Scans data segments for magic constants (e.g. S-boxes, hash IVs, zlib tables), renames matched arrays and bookmarks them for rapid navigation.
* [Virtuailor](https://github.com/0xgalz/Virtuailor): Reconstructs C++ vtables (x86/x64/AArch64) by statically detecting and dynamically hooking indirect calls, then creates vtable structs, renames functions, and adds cross-refs.
* [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp): Embeds an HTTP/SSE “Model Context Protocol” server in IDA, exposing decompilation, disassembly, symbol and string queries, and rename/comment APIs for AI or script integration.
* [Class Informer](https://github.com/kweatherman/IDA_ClassInformer_PlugIn): Parses MSVC RTTI in PE files to auto-generate class hierarchies, structures, vtable/method names, and presents them in an interactive browser.
* [IDA Medigate](https://github.com/medigateio/ida_medigate/): Offers an API for manual C++ class/polymorphism definitions (useful when RTTI is stripped) and includes a g++ RTTI parser to rebuild class layouts without extra UI clutter



I signed up for the Claude Pro plan and asked the AI to connect to the IDA database through MCP to automatically perform static code analysis. To help the AI analyze the decompiled code more accurately (since its initial attempts were pretty far off), I provided some context from my own manual analysis and the results from other tools. The AI did rename some functions and variables on its own, though there’s definitely room for improvement—like making the code look more like actual C++. I also realized I needed to brush up on proper C++ reverse engineering, since this process clarifies the code’s logic but doesn’t fully restore the original syntax.

![](assets/uxcO6S0_bCUyHZ3nKYVBctnHbD8pUJQN7EzzxNsIp3o=.png "A snippet of the code that me and the AI reverses, as you can see there are still much to do like Add Type Information, Reconstruct class and structure and additional variables renaming")



Digging into this would take a while, so I kicked things off with some dynamic analysis. I spent ages just trying to get it running, because the malware has an IsDebuggerPresent() check right in the middle of its runtime, and I couldn’t figure out how to get around it in IDA 8.3 (at least not without wasting even more time). So, I just downgraded to 7.5 and used ScyllaHide to get past it.

It’s super helpful to have Process Monitor running to see what the malware’s doing to the system, while also dropping breakpoints in the code. After poking around with some static analysis, I noticed the AES key and IV get passed to ProcessKeyFilesAndVerify, so I set a breakpoint there in the main encryption flow. Before that, the malware just scans directories and grabs all the files on the system, getting ready to encrypt them in the next step.

![](assets/7naWDzV4AJFH78gvul5Hs9UnHHFT1SfTiFv6E-lUvwE=.png "Querying Directory and Files")

The AES key is loaded into rcx, while the IV is loaded into rdx. Noticed the AES key only has 31  while AES-256 require 32 bytes. Would have to pad the key later on.

![](assets/ulX-Hgt6eg99E8uXS_fIlsh8HrbG5rIyOzydiz1E0NE=.png "ProcessKeyFileAndVerify")

I still have to verify if these are the actual keys that were used to encrypt the files because the malware has a bunch of other cryptographic mechanisms built in, e.g RSA cryptography which was a big distraction to me and led me to a rabbit hole. Set up a break point inside ProcessKeyFileAndVerify function:


![](assets/jNktVHtJl6597ENk7PNvZZbZBlVzvI7vqn7p1nDo0pE=.png "Breakpoint in ProcessKeyFIlesAndVerify")

Hit F9 and check Process Monitor. It is encrypting team06.pdf (I created this sample file) to team06.pdf.sbc.0yk. Hit F9 again and it will be encrypting another file. So definitely, this function is looping through a list of files it was collecting prior to this and then highly likely applying AES encryption afterwards.

![](assets/pSt7STFRpudRLznJ4YRH9UmDfkh3P341lS-j3epPRA8=.png)

So we know it was using AES, to decrypt files in the dump, we need to locate the keys in the dump. So we have to mirror things from our test environment, see which regions do the AES keys reside in. I'm using to deReferencing plugin to look at the values of the stacks (it would know if data pointed to is memory or some strings or some other values, way more helpful than IDA stack).

![](assets/ESI--0ytqsz2TQMku4XacOqzt5RycEEMLV6MRls9sqY=.png "Stack at the breakpoint")

I noticed that every time I F9ed, the address which the string "Microsoft Strong Cryptographic Provider" resided at never changed its value, so I used the string as an anchor. At the lower memoery addresses were the key and the IV.

![](assets/wNG0VSdGIfwcjkUmVgjl5YeoksvRerQF5gqCqNmJrZI=.png "AES key and IV found.")

Applying this to the memory dump, I wrote a script (The AI actually wrote it) to scan for the string "Microsoft Strong Cryptographic Provider" and it previous and after bytes in the pid.7008.dump ( Gotta dump the malware process out of the whole system dump).

![](assets/Xfd562OXa1v3Mzd8aG3me2OJ7icLHZyh_g6V6QO43dg=.png "Key and IV dumping.")

The AES key can be found easily above the string. But there are many potential IV (as denoted by the arrow). The IV has 16 bytes and highly likely it wouldn't have many 00 bytes inside it so I asked the AI to auto denote the potiential candidate for the IV. I'm lazy so I combine all of the bytes into a files, then ask the AI to try the sliding window method for all potential IV values. 

```
PS C:\1day\malware-analysis\bootcamp2024> cat .\iv.txt
  00 02 00 80 6B 51 66 50 78 5A 37 32 32 50 48 6F 76 72 6A 70 71 42 7A 4C 4D 63 51 4D 62 59 54 6F 00 00 00 00 1F 21 56 0F  31 A0 6F 4D A8 79 4D FA  15 6D 3E 0A 00 00 00 00  00 00 00 00 53 7B 87 AE
00 16 00 90 48 3E 65 66  55 35 63 21 39 50 46 71  56 33 58 66 00 00 00 00  00 00 00 00 00 00 00 00 00 1D 00 80 6B 51 66 50  78 5A 37 6E 30 61 43 6B  72 2B 4C 70 34 42 44 53  4C 5A 42 51 66 39 48 33
  00 1E 00 80 6B 51 66 50  78 5A 37 32 32 50 48 6F 6B 4C 36 79 37 52 62 35  62 49 68 66 4E 4D 66 30
```

A succesful decryption happens when the original team06.pdf.sbc.0yk is recognized as a pdf after decryption. That took 69 attempts. The IV was 483EXX... The decryption code can be found [here](https://gdrives.ghtk.co/s/3SaEAwcHJn4WLBR?dir=undefined\&openfile=26767328). We have succesfully decrypted the file.

![](assets/KbvqGwCyo7tspDdPMPsnVTQf4eapwOLkyLyEgfLlJuo=.png)



With enough context, AI is now able to get to the root of reverse engineer problems easily. For C++, currently the MCP plugin hasn't supported class and struct reformat so the decompiled code looks more human-readable though.

