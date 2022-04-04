---
title: Bypass SSL Pinning in Flutter using IDA
tags: [Android]
style: border
color: warning
description: Flutter is a free and open-source mobile UI framework. Hackers and penetration testers can bump into some problems with certificates and ssl pinning when testing applications built with Flutter.  This article is a detailed guide to solve all that bs.
---

Flutter is a free and open-source mobile UI framework. Hackers and penetration testers can bump into some problems with certificates and ssl pinning when testing applications built with Flutter.  This article is a detailed guide to solve all that bs.

## What is SSL Pinning?
Your HTTPS connection is secured by a certificate, which is created from a public and private key pair.  SSL Certificate Pinning is the process of associating a host with its certificate (the public key). The application will only trust the predefined certificate (instead of custom certificate which can be altered by attacker ). This is an additional security measure to prevent attackers from analyzing the application by intercepting traffic. In general, there are two techniques for pinning the certificate:

- <span style="color:#e5202a"> Pin the certificate</span>: The app developer downloads the server certificate, put it in the app bundle and performs comparison at runtime
- <span style="color:#e5202a">Pin the public key</span>: Include the public key in the application bundle as a hash, compares the public-key at runtime with the hash.

## Flutter and Dart
Honestly, you don't need to know what Flutter is, just know it's a framework. To develop with Flutter, a programming language called Dart must be used.

Dart uses the <span style="color:#e5202a"> HttpClient</span> class as a standard implementation to send http request. Another class, SecureSocket is responsible for establishing a secure connection. If there's a failure, a handler function can be triggred. 

This function can be registered using badCertificateCallback in HttpClient. Apart from letting us know that the certificate is compromised, the function can also handle this issue. At this point we have to decide whether we continue with this request or not.

