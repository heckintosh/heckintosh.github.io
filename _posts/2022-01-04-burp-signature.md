---
title: Handling requests containing signatures with Burp Suite
tags: [Encryption, Burp]
style: border
color: info
description: Many mobile applications include signatures for requests nowadays, making scanning and repeating requests infeasible. Fortunately, there is a way to deal with this issue in Burp.
---

CSTC: [The only tool you will need.](https://github.com/usdAG/cstc)

As a hacker, one would like to be able to examine a request, alter and replay it to probe for application vulnerabilities in inputs. Such a trivial task turns out to be a hassle because more and more devs are adding signatures to requests sent to applications, causing repeated/altered requests to fail. This article will help you deal with that problem. 

## 1. What is a signature?
Let's start with real life signature. Look below:

{% include elements/figure.html image="https://i.imgur.com/AHXsgDlm.png" caption="My beautiful signature" %}

Now every documents that have this signature definitely come from me. Or are they? Let's be real, it will probably take you max 10 tries to replicate my signature. In primary school, after every exams, the teachers would always make us bring the exam papers (with grade on it) for our parents to sign on and then submit back to the teacher later. Imagine what the students can do to circumvent that :thinking:. <b>Real life signature is used to serve as a symbol of agreement, similar to a handshake, instead of a verification for people's identities</b>.

Digital signature offers better security compared to handwritten signature. The document information is embedded in the digital signature through the magic of cryptography. If any information is changed in the document request the signature becomes invalid. It adds authenticity and integrity.

## 2. Why even include a signature:
When:
- The request is already transported through HTTPS.
- The request already contains an Authorization header or some forms of token.

Both of the above mechanisms are implemented to protect API security, but none of them fully guarantees the <span style="color:#e5202a">integrity</span> of the request or that  the request is not <span style="color:#e5202a">replayable/repeatable</span> (pain to both hacker and tester :rofl:).

By using HTTPS, tampering can be prevented during transit but it <b>cannot</b> be assumed that the request was `not sniffed and modified by the attacker`:
- Before the request is HTTPS encrypted (at the client side by another malicious (or not) software).
- At the server side, by a sniffer placed between the HTTPS endpoint and the actual server. For this case, the HTTPS encryption/ decryption process is handled by a load balancer or a reverse proxy, so there is a possibility for sniffing traffic between those two servers.

## 2. Components of a signature:
How to create a signature is fully dependent on the developer, but most of the applications out there follow [this IETF standard](https://tools.ietf.org/id/draft-cavage-http-signatures-08.html#rfc.section.2.1).

Belows is an example of a request containing signature, based on a real Android app:

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

The following elements together contribute to building the `Signature` header in the above example:
- `keyId`: A string for the server to look up the component they need to validate the signature. 
- `secretkey`: A secret key .
- `created`: Unix time on which the request is created.
- `Authorization`: a token for authentication (in the format of JWT typically but i'm lazy to generate one).
- `Digest`: B64 encoded body of the request.
- `signature`: This parameter is a b64 encoded digital signature. The client uses an algorithm and a <span style="color:#e5202a">sign pattern</span> (consists of a list of concatenated value that developers choose) to form a  <span style="color:#e5202a">signing string</span>. This <span style="color:#e5202a">signing string</span> is then signed using the secret key associated with keyId and the algorithm. The signature parameter is then set to the b64 of itself

Sometimes it is obvious how the signature is composed, but most of the time you will have to do some reverse engineering on the application to figure out the logic:
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
auth = "31337"
sign_pattern = "keyId={},digest={},created={},auth={}".format(keyId, digest, created, auth)
signature = base64.b64encode(hmac.new(secretkey,bytes(sign_pattern,'utf-8'),hashlib.sha256).digest()).decode("utf-8")
Signature = "keyId={},created={},signature={}".format(keyId, created, signature)
```


## 3. Introducing CSTC: A Burp extension for manipulating HTTP requests
{% include elements/figure.html image="https://cdn-images-1.medium.com/max/1000/0*nF_H2-8oTY7C0a54.png" caption="Android" %}

Apple and Google also fairly recently rolled out time management tools which allow the user to be restricted from certain applications after a given amount of use. This really helps to add an extra layer of discipline if you’re trying to build the habit of using your phone less.

Minimalism isn’t a philosophy that demands you to sell everything you own, wear the same outfit for the rest of your life, and live out of your van. Rather, it’s taking a hard look at everything in your life and determining whether something truly provides happiness for you. Digital Minimalism is a subset of this way of thinking and is a philosophy that has allowed me to work in tech and be an active participant of social media, but also maintain my own level of free thinking and choose what I focus on.

I hope this has helped at least one person out there better manage their digital engagement. When I was first starting my foray into this way of thinking, this documentary by Matt D'Avella really helped me understand what minimalism was all about and is something I’d recommend if you’d like to learn more!