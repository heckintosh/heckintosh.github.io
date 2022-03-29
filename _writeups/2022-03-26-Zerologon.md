---
name: Recreating the CVE-2020-1472 (the Zerologon attack)
tools: [CVE, AD, Windows, Recreated]
image: https://ophtek.com/wp-content/uploads/2020/10/zerologon.png
description:  Recreating the infamous Zerologon attack on Windows Active Directory.
---

I am going to take the OSCP exam soon and almost all big corps (including my company) are using Active Directory (AD) in their infrastracture so I figure it wouldn't be a waste of time digging into some good old AD vulnerabilies to understand the security aspect of this massive tech product better. This is a short blog where I explain the Zerologon attack on AD (and how I recreate it) as clear as possible. Kudo to Secura for providing an execellent [article](https://www.secura.com/uploads/whitepapers/Zerologon.pdf) regarding this vulnerability. 

## Zerologon overview

This CVE allows an unauthenticated attacker with network access to a domain controller, to establish a Netlogon session and eventually gain domain administrator privileges. This vulnerability is considered a privilege escalation vulnerability.

## What is Netlogon Remote Protocol (MS-NRPC)?
This attack is due to a cryptographic flaw in MS-NRPC. So let's dive into the protocol details.

[MS-NRPC](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f) existed to maintain
the relationship between a domain member and its domain, and relationships among domain controllers (DC) and other machines in the domain. So there are certain criteria it needs to meet:

1. Able to setup a secure channel that is used by domain members to talk with the DC.

2. Able to pass authentication requests from domain members to DC, and among DCs. Used by NTLM, Kerberos and Digest.

3. Able to transmit certain account changes, for example password changes or account lockout information.

The protocol is described in details [in this Microsoft document](https://winprotocoldoc.blob.cor
e   .windows.net/productionwindowsarchives/MS-NRPC/[MS-NRPC]-170601.pdf).

Below is a simplified diagram for the steps performed by a client and a server implementing NETLOGON when <span style="color:#f88949">establishing a secure channel</span>:

{% include elements/figure.html image="https://i.ibb.co/yVv72bG/final-netlogon.png" caption='NETLOGON authentication handshake' %}

Unlike many other challenge-response protocols, NETLOGON employs [mutual authentication](https://en.wikipedia.org/wiki/Mutual_authentication) which means that both side will do the authentication work.  The server ensures that the client knows the secret, and the client also ensures that the server knows the secret, which prevents impersonation of the server.  

Two 8-byte nonces (challenges) are first exchanged. An unpredictable session key is them computed using a [Key Derivation Function](https://crypto.stackexchange.com/questions/40757/key-derivation-functions-kdf-what-are-main-purposes-how-can-they-be-used). 

The session key computation is documented by Microsoft [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/77334f84-8fef-4b5f-a55e-1125f9e6adae). Below is my pseudocode for it:

```python
challenges = client_challenge + server_challenge # 16 bytes total
shared_secret = GetClientPass() # Shared secret since both client & DC stores the client pass 
hash_secret = MD4(shared_secret)
key = HMAC256(hash_secret, challenges)[:16]
```


This is effective against MITM, since the attacker does not know the secret (in this case the hash of the client's password) even if he can sniff out the challenge. Later, messages will be transfered encrypted with this session key.


## Zerologon in depths

So what is wrong here? [CVE-2020-1472](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)  exploits a cryptographic flaw in the protocol. The bug is in the orange text (<span style="color:#f88949">the encrypt function</span>) in the diagram above :wink::

```python
client_cred = encrypt(iv, session_key, client_challenge)
server_cred = encrypt(iv, session_key, server_challenge)
```

There are three versions of the encrypt function: [AES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/77334f84-8fef-4b5f-a55e-1125f9e6adae), [Strong-key](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/7226b8dc-a5b5-46e8-83a8-97e412d1f46e) and [DES](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3c79af30-6203-4fb6-9e1d-8e6a205f7b3d).  The vulnerability comes from the implemented AES scheme, in particular the usage of the <span style="color:#e5202a">AES-CFB8</span> block cipher mode of operation. You might want to read this [comic](http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html), it is an effective way to visualize AES. I dig up and write about the AES block cipher modes of operation because it is related to this vulnerability (and because it is short).

#### AES modes of operation
AES is a block cipher. It takes a block of 128 bits and encrypts or decrypts it using the key.  

In real life, we probably want to encrypt more than a block of few bits. Either we have to create more block ciphers of every size (which is dumb) or we create a method to use existing block cipher like AES to encrypt more data. This method is called "mode of operation".

The most simple mode is <span style="color:#e5202a">ECB</span>. We simply divide the plaintext into section of 128 bits, if its not a multiple of 128 then we'll do some padding. Each section is then encrypted with AES, concatenate them and we have the result.

{% include elements/figure.html image="https://i.ibb.co/kQw4gKX/ecbmode.png" caption='' %}

> Some sideline fun fact: ECB is not very secure since it lacks a cryptography principle which is diffusion. More on [this](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).

Related to ZEROLOGON, let's do some digging into the Cipher Feedback (CFB) mode.

#### Cipher feedback (CFB)
For CFB mode, the encryption process is "take the most recent ciphertext block, pass it through the block cipher (AES) and then XOR that with the plaintext block to generate the next ciphertext block". B-But what about the first block? Well, there's something called the Initialization Vector (IV), it's used for encrypting the first plaintext block because previously there is no ciphertext block.

{% include elements/figure.html image="https://i.ibb.co/qdzNYkx/cfb-mode-full.png" caption='' %}


#### CFB8
Okay, we have CFB, but what about CFB8? The diagram below should give you a clear visualisation.

{% include elements/figure.html image="https://i.ibb.co/tCvQxG4/aes2.png" caption='CFB8 mode' %}

Things get a little convoluted.  You still use the 16 bytes IV, but each time the 16 bytes output comes out of the block cypher encryption, only s bits (s here can be 1, 8, 64 or 128 depending if you use CFB1, CFB8, CFB64 or CFB128, in this case it is 8) of the output is used to calculate an <span style="color:#e5202a">8-bit ciphertext block</span> by XORing with 8 bit of the plaintext. The remaining 128-8 bit (of the IV or of multiple blocks of ciphertext) plus the previous <span style="color:#e5202a">8-bit cipher block</span> is used as input for the next cycle. The advantage here is that 1 character equals 8-bit so we can encrypt every single character without having to do any padding.

The main vulnerability here is from Microsoft's NETLOGON implementation of CFB8 and it can be easily summed up with this:

{% include elements/figure.html image="https://i.ibb.co/S0d6ZW7/Disloyal-Man-24032022135348.jpg" caption='' %}

The initialization vector is typically required to be random. But in Microsoft's encrypting function, <span style="color:#e5202a">the IV is fixed and consists of 16 zero bytes</span>. What we can control is the plaintext and we have an all-zero IV, but the key is randomly generated by the server. Remember AES gotta output something and all 8 bits that it puts out ranges in : `00 to FF` (256 values) when represented in hex.

So I ran some code flipping the last hex of a key and one of the 256 keys will result in the first hex of the cipher being `00`.

{% include elements/figure.html image="https://i.ibb.co/NZLpxtx/cfb-fullmode.png" caption='' %}

Hmm :thinking:, what would happen to the final cipher text of CFB8 if the first cipher byte is `00`? 

{% include elements/figure.html image="https://i.ibb.co/pZFt1Nx/cipher-full-zeros.png" caption='Much zero very secure' %}

As you can see above, as attacker, we can control the plaintext (the client challenge), set it to zeros resulting in <span style="color:#e5202a">a ciphertext of full zeros</span> (after bruteforcing around 256 times to get the first byte that AES outputs to be `00`). 

#### So what?

The NETLOGON flow will become like this when the cipher is all zeros:

{% include elements/figure.html image="https://i.ibb.co/J3jYTs7/sskeynegotiation3.png" caption='' %}

Remember this CVE requires an attacker to have access in the network (the ability to talk to the DC). The scenario here is that the attacker can be an internal employee or the attacker has already taken control of an internal machine. He now can use this CVE to try to access information from other machines or the DC without knowing their credentials. 

The verify & compare step is just the client/ server taking the challenge from each others and apply the encryption algorithm to it. With the client credential being all 0 and the server will also verify that the client credential is valid, the attacker is now authenticated as if he is a valid user. However, the next step is to setup a secure channel to transport between the client and the server, which utilizes the session key. 

> The CVE does not use a valid session key. Every time an authentication call is made, an unique key is generated since the server gives out a different server challenge. But there will be eventually one key that makes the server's verification of the client credential return TRUE.

The attacker has no idea what the session key is because the session key is constructed from the client's password and the algorithm to encrypt the channel is not vulnerable like the one used to client's cred function. Conveniently, the client can modify the NetrServerAuthenticate3 params and the server will be happy with no encryption for the channel at all :rofl:.

> NetrServerAuthenticate3 is the call from client to server and its param contains the client credential, right before establishing the secure channel. The method mutually authenticates both sides.


```csharp
 NTSTATUS NetrServerAuthenticate3(
   [in, unique, string] LOGONSRV_HANDLE PrimaryName,
   [in, string] wchar_t* AccountName,
   [in] NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType,
   [in, string] wchar_t* ComputerName,
   [in] PNETLOGON_CREDENTIAL ClientCredential,
   [out] PNETLOGON_CREDENTIAL ServerCredential,
   [in, out] ULONG * NegotiateFlags, //Set to 0x212fffff, sign/ seal flag is disabled
   [out] ULONG * AccountRid
 );
```

By setting the sign flag to 0 we can bypass the secure channel step. The doc for `NegotitateFlags` can be found [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5805bc9f-e4c9-4c8a-b191-3c3a7de7eeed).

So the exploit flow can now be simplified to this: 
![NetrServerAuthenticate3](https://i.ibb.co/nD2BWqw/netserverauthenticate4.png)


#### Perform a call
Annoyingly, there are several more steps til we can reach the true exploit. Any calls that are remotely interesting requires the Authenticator parameter as you can see below:

```csharp
NTSTATUS NetrServerPasswordGet(
   [in, unique, string] LOGONSRV_HANDLE PrimaryName,
   [in, string] wchar_t* AccountName,
   [in] NETLOGON_SECURE_CHANNEL_TYPE AccountType,
   [in, string] wchar_t* ComputerName,
   [in] PNETLOGON_AUTHENTICATOR Authenticator,
   [out] PNETLOGON_AUTHENTICATOR ReturnAuthenticator,
   [out] PENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword
 );
```

But the authenticator is also computed using the vulnerable function, so that solves that :grin:. Just set the authenticator to all 0s (and an additional timestamp parameter to 0) and when the server validates the authenticator, the result will be 0 and the call will be valid.

We can exploit the NetrServerPasswordSet2 call. 

```csharp
 NTSTATUS NetrServerPasswordSet2(
   [in, unique, string] LOGONSRV_HANDLE PrimaryName,
   [in, string] wchar_t* AccountName,
   [in] NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType,
   [in, string] wchar_t* ComputerName,
   [in] PNETLOGON_AUTHENTICATOR Authenticator,
   [out] PNETLOGON_AUTHENTICATOR ReturnAuthenticator,
   [in] PNL_TRUST_PASSWORD ClearNewPassword
 );
```


This is utilized to set a new computer password for the client. Per [Microsoft documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/52d5bd86-5caf-47aa-aae4-cadf7339ec83):

>The NL_TRUST_PASSWORD structure is <span style="color:#e5202a">encrypted using the negotiated encryption algorithm</span> before it is sent over the wire. 

So you have to specify the new password to set and that password is needed to be encrypted with the session key (again :tired_face:!?). We do not know the session key so the server will reject this during validation. Luckily, the same vulnerable algorithm is applied to this password as well so we can just set it all to zeros and we are good to go. <span style="color:#e5202a">The DC will happily accept an empty password </span>. So we know the account has an empty password and we can proceed to set it to another password if we prefer to. We can even escalate this to change the password of the DC.

## Recreation
You only need to have one DC and one attacking machine to replicate this attack. But I add one more client just to understand this vulnerability better. 

| Role              | OS                     | IP           |
|-------------------|------------------------|--------------|
| Domain Controller | Windows Server 2012 R2 | 192.168.5.1  |
| Domain Member     | Windows 10             | 192.168.5.2  |
| Attacking machine | Kali                   | 192.168.5.3  |

There are a bunch of POCs around the Internet at this time so I'm not going to waste time on creating a new one. Here are a list of tools I'm going to use to demonstratre this attack:

| Tool              | Description |
|-------------------|------------ |
| impacket          | a collection of Python classes for working with network protocols |