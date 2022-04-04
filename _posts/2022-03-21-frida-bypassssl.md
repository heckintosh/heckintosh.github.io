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


If we do not add a handler, the connection will be terminated following the certificate verification failure.

How does SecureSocket verify certificates? The standard behavior in this case would be to check for certificates registered in the system. But, as we have said before, this would not be the best approach for a reliable verification. Being able to verify a specific certificate or a certificate chain is crucial here.

In Dart, the SecurityContext class can solve this issue. As stated in the description of this class, it is an object that contains certificates to trust when making a secure client connection as well as the certificate chain and private key to serve from a secure server. This object can be passed on to HttpClient upon its creation. In this case, the client will rely on the data stored in the context for verification regardless of whether or not the system trusts these certificates.

SecurityContext can be created using various constructors, therefore the contents will differ depending on the constructor. For instance, the default constructor creates a completely empty context without any registered keys.
*
But if we take SecurityContext.defaultContext, it creates a context containing some sets of trusted certificates depending on the system. On Windows or Linux, the Mozilla Firefox certificate storage is used. In case with MacOS, iOS and Android only those certificates get registered that the system considers trustworthy.

In addition, the context contains methods for registering private keys, trusted certificates and certificate chains.

In order to register a trusted certificate, you can choose one of two methods.
void setTrustedCertificates(String file, {String password});
This method allows you to specify the path to the certificate.
void setTrustedCertificatesBytes(List<int> certBytes, {String password});
It uses the certificate content as bytecode for registration.
In my opinion, it is better to use setTrustedCertificatesBytes, and the developers actually warn us:

NB: This function calls [File.readAsBytesSync], and will block on file IO. Prefer using [setTrustedCertificatesBytes].


The reason behind this is quite simple. If some ill-wisher wanted to harm us, it would require a great deal of effort. We cannot just put the certificate file in the resources as a regular file, it is easy to find and replace by decompiling. Although the attacker will not be able to sign the rebuilt app, no one can do more harm to the user than the user themselves. Therefore, the inability to re-sign an app using the same keys may not be a decisive factor.
What if we build the key into the app as bytecode? Since Flutter uses AOT compilation when building apps in release mode, it will make things quite difficult for anyone who wants to replace the certificate by cracking the app.


