---
toc: true
title: Flagyard
description: Flagyard
date: 2023-12-13
author: Duc Anh Nguyen
---

### Pwn: Babyauth

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *secret;

__attribute__((noreturn))
void fatal(const char *msg) {
  printf("[-] %s\n", msg);
  exit(1);
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  if (!(secret = getenv("SECRET")))
    fatal("App secret is not set");
}

void getval(const char *msg, long *v) {
  printf("%s", msg);
  if (scanf("%ld%*c", v) != 1)
    fatal("I/O Error");
}

void getstr(const char *msg, char *s, int len) {
  printf("%s", msg);
  if (!fgets(s, len, stdin))
    fatal("I/O Error");
  s[strcspn(s, "\n")] = '\0';
}

int main() {
  int is_admin, len;
  char *password;

  is_admin = 0;
 // Integer overflow here at getval, enter 60000000000 and we are able to overflow the is_admin variable to turn it into 1 without having to enter the correct password. Why 60000000000? I figured it out by trial and error in gdb.
  getval("length: ", (long*)&len);     
  if (!(password = (char*)malloc(len + 1)))
    fatal("Memory Error");

  getstr("password: ", password, len); //
  if (strcmp(secret, password) == 0)
    is_admin = 1;

  free(password);

  if (is_admin == 1) {
    puts("[+] Authenticated");
    system("/bin/sh");
  } else {
    puts("[-] Authentication failed");
  }

  return 0;
}
```

`Flag: FlagY{tYp3_c0nfUs10n_m4k3s_a_b4D_r3sULt}`
 