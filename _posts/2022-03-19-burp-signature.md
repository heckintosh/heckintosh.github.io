---
title: Handling HTTP signed requests with Burp Suite
tags: [Signature, Burp Suite, Android]
style: border
color: info
description: Many Android applications include signatures for requests nowadays, making scanning and repeating requests difficult. Fortunately, there is a way to deal with this issue in Burp using an extension called Cyber Security Transformation Chef (CSTC).
---

TLDR: [Use CSTC -> A Burp extension](https://github.com/usdAG/cstc)

As a hacker, one would like to be able to examine a request, alter and replay it to probe for application vulnerabilities in inputs. Such a trivial task turns out to be a hassle because more and more devs are adding signatures to requests sent to applications, causing repeated/altered requests to fail. This article will help you deal with that problem. 

## 1. What is a signature?
Let's start with real life signature. Look below:

{% include elements/figure.html image="https://i.imgur.com/AHXsgDlm.png" caption="My beautiful signature" %}

Now every documents that have this signature definitely come from me. Or are they? Let's be real, it will probably take you max 10 tries to replicate my signature. In primary school, after every exams, the teachers would always make us bring the exam papers (with grade on it) for our parents to sign on and then submit back to the teacher later. Imagine what the students can do to circumvent that :thinking:. 

> <b>Real life signature is used to serve as a symbol of agreement, similar to a handshake, instead of a verification for people's identities</b>.

Digital signature offers better security compared to handwritten signature. The document information is embedded in the digital signature through the magic of cryptography. If any information is changed in the document request the signature becomes invalid. 

{% include elements/figure.html image="https://i.ibb.co/f4tHNJw/digsig6.png" caption="Digital signature creation and verification flow" %}

Not many articles I have found on the Internet mentioned this, but there are 2 ways to implement creation and verification of digital signature. The above figure describes using only one shared key for signing and verifying (done with a symmetric algorithm such as HMAC256). The other way is to have a pair of public key and private key (done with an asymmetric algorithm such as RS256), where signature generated with the private key can be validated with the public key. 

[HMAC](https://en.wikipedia.org/wiki/HMAC) helps prevent manipulation by an actor who has not access to the secret:
 - prevent manipulation by the client if the secret is only known to the server (e.g: verify a request actually comes from an Android app, shared key obfuscated in the code). 
 - prevent manipulation in transit if the secret is known to client and server.

[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) signature can be used to:
- prevent manipulation.
- allow those with the public key to verify the integrity and source of the data without being able to manipulate the data.


> <b><u>Note:</u></b> The traditional understanding of RSA is "public keys encrypt, private keys decrypt". For signatures, things are backwards. You are attempting to prove the message is signed by you and came from you. So you need to have your own private key. This is inherently a little more secure than HMAC but you can see the hassle behind it when trying to implement it in a traditional Android web application, each clients must have their own key pairs and the server needs to have information on which public keys belong to which clients. 

> Choosing the algorithm therefore depends on your use case. In case the server just wants to guarantee no token manipulation is going on, the client can implement HMAC with a server side secret.

For more details, you can checkout [this video](https://www.youtube.com/watch?v=s22eJ1eVLTU) on digital signature and [this video](https://www.youtube.com/watch?v=NmM9HA2MQGI) on how to exchange the key pair securely.


## 2. Why even include a signature:
When:
- The request is already transported through HTTPS.
- The request already contains an Authorization header or some forms of token.

Both of the above mechanisms are implemented to protect API security, but none of them fully guarantees the <span style="color:#e5202a">integrity</span> of the request or that  the request is not <span style="color:#e5202a">replayable/repeatable</span> (pain to both hacker and tester :rofl:).

By using HTTPS, tampering can be prevented during transit but it <b>cannot</b> be assumed that the request was `not sniffed and modified by the attacker`:
- Before the request is HTTPS encrypted (at the client side by another malicious (or not) software).
- At the server side, by a sniffer placed between the HTTPS endpoint and the actual server. For this case, the HTTPS encryption/ decryption process is handled by a load balancer or a reverse proxy, so there is a possibility for sniffing traffic between those two servers.

## 3. Components of a signature:
How to create a signature is fully dependent on the developer, but most of the applications out there follow [this IETF standard](https://tools.ietf.org/id/draft-cavage-http-signatures-08.html#rfc.section.2.1).

Belows is an example of a request containing signature, created with a shared key, based on a real Android web app:
```http
POST /api/checkversion HTTP/2
Host: api.heckintosh.vn
User-Agent: Dart/2.12 (dart:io)
Accept-Encoding: gzip, deflate
Content-Length: 46
Authorization: Bearer 31337
Signature: keyId=key-heckintosh,created=1642617796,signature=P5AAtQW4qPFUZxwOabNfEZsAhYtz2/eRnu/KvyeCe6Q=
Digest: nNAoy4A0Mp9EhFKOGLW0B9hdAELIkQbhUSwvmae2Csg=
Content-Type: application/json; charset=utf-8
Connection: close

{"AccountName":"heckintosh","Version":"1.0.0"}
```

> You need to know to catch Android webapp requests with a proxy like Burp to get the above request.

The following elements together contribute to building the `Signature` header in the above example:
- `keyId`: A string for the server to look up the component they need to validate the signature. 
- `secretkey`: A secret key .
- `created`: Unix time on which the request is created.
- `Authorization`: a token for authentication (in the format of JWT typically but i'm lazy to generate one).
- `Digest`: B64 encoded body of the request.
- `signature`: This parameter is a b64 encoded digital signature. The client uses an algorithm and a <span style="color:#e5202a">sign pattern</span> (consists of a list of concatenated value that developers choose) to form a  <span style="color:#e5202a">signing string</span>. This <span style="color:#e5202a">signing string</span> is then signed using the secret key associated with keyId and the algorithm. The signature parameter is then set to the b64 of itself
- `Signature`: Concatenation of <span style="color:#e5202a">keyId</span>, <span style="color:#e5202a">created</span> and <span style="color:#e5202a">signature</span>.

> Sometimes it is obvious how the signature is composed, but most of the time you will have to do some reverse engineering on the Android application to figure out the hardcoded key and the algorithm behind creating the signature. Below is how this example application generates the digest plus signature header and appends them to the parameter.

```python
import time
import base64
import hmac
import hashlib
request_body = b'{"AccountName":"heckintosh","Version":"1.0.0"}'
keyId = "key-heckintosh"
secretkey = b"cf1337cd-a133-1337-acac-a337bece1337"
created = int(time.time())
dig = hmac.new(secretkey,request_body,hashlib.sha256)
digest = base64.b64encode(dig.digest()).decode("utf-8")
auth = "Bearer 31337"
signstring = "keyId={},digest={},created={},auth={}".format(keyId, digest, created, auth)
signature = base64.b64encode(hmac.new(secretkey,bytes(signstring,'utf-8'),hashlib.sha256).digest()).decode("utf-8")
Signature = "keyId={},created={},signature={}".format(keyId, created, signature)
```


## 4. CSTC: A Burp extension for manipulating HTTP requests
For these signed requests, it is max pain to manually create a valid request. Fortunately, the [Cyber Security Transformation Chef (CSTC)](https://github.com/usdAG/cstc) extension made by usd AG is available on Burp for us to turn Repeater request to a valid request.

> Use a light theme for CSTC. It has a [bug](https://github.com/usdAG/cstc/issues/55) with the dark theme

{% include elements/figure.html image="https://i.ibb.co/chCXFnv/cstc.png" caption="CSTC UI" %}

What is special about this extension? Well, you can define variable, pipe them through a cryptography function and obtain the output. Initialize a variable with that output as the value, then replace a part of the request with that variable.

This is the unsigned request from the above example:

```http
POST /api/checkversion HTTP/2
Host: api.heckintosh.vn
User-Agent: Dart/2.12 (dart:io)
Accept-Encoding: gzip, deflate
Authorization: Bearer 31337
Content-Type: application/json; charset=utf-8
Connection: close

{"AccountName":"heckintosh","Version":"1.0.0"}
```


I'll demonstrate step by step how to append the following two values automatically to the request with CSTC so that it becomes signed:

```
Signature: keyId=key-heckintosh,created=1642617796,signature=P5AAtQW4qPFUZxwOabNfEZsAhYtz2/eRnu/KvyeCe6Q=
Digest: nNAoy4A0Mp9EhFKOGLW0B9hdAELIkQbhUSwvmae2Csg=
```

{% include elements/figure.html image="https://i.ibb.co/K9fKNCS/step1-2.png" caption="1. Obtain keyId and secret keys through reverse engineering and assign those values to variables" %}

{% include elements/figure.html image="https://i.ibb.co/kgXw1vY/step2.png" caption="2. Extract the request body and store it as variable <i>req_body</i>" %}

{% include elements/figure.html image="https://i.ibb.co/dPDfry7/step3.png" caption="3. Get the current time and store it as variable <i>created</i>" %}

{% include elements/figure.html image="https://i.ibb.co/xX56VSj/step4.png" caption="4. Create a base64 digest from the request body and store it as variable <i>digest</i>" %}

{% include elements/figure.html image="https://i.ibb.co/s1QsWsw/step5.png" caption="5. Get the auth header and store it as variable <i>auth</i>" %}

{% include elements/figure.html image="https://i.ibb.co/Pgv7nG9/step6.png" caption="6. Create the sign string and stores it as variable <i>sign_string</i>" %}

{% include elements/figure.html image="https://i.ibb.co/RbSy15H/step7.png" caption="7. Create the base64 encoded signature from the signing string and the secret key " %}

{% include elements/figure.html image="https://i.ibb.co/yyWS2ZP/step8.png" caption="8. Append the signature and digest header to the request" %}

{% include elements/figure.html image="https://i.ibb.co/1swfcz9/final.png" caption="Finally, check the input and output to the right" %}

Tick the CSTC option to allow it to modify Repeater request and now you can all go replaying signed Android traffic using this amazing extension. One last thing though, the current version of CSTC is buggy in Windows and in Burp Suite dark mode, but my tests run great in Linux and default Burp light mode. 

{% include blog/donation.html %}
