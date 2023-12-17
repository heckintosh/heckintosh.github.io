---
toc: true
title: Wargames.my
description: Wargames.y
date: 2023-12-16
author: Duc Anh Nguyen
---


0000050015

```asm
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