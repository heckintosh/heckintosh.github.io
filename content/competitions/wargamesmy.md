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
<details>
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

Enter 050015 should satisfy first condition and atoi will ignore leading zero also. Now it's just ret2libc for the `magic_door` function (since NX is enabled so no shellcode). Leak the libc address via puts.

<details>
<summary>solve.py</summary>
</details>


## [2. Pwn: ]