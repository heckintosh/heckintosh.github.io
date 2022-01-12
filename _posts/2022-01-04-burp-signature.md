---
title: Handling requests containing signatures with Burp Suite
tags: [Encryption, Burp]
style: border
color: info
description: Many mobile applications include signatures for requests nowadays, making scanning and repeating requests infeasible. Fortunately, there is a way to deal with this issue in Burp.
---

CSTC: [The only tool you will need.](https://github.com/usdAG/cstc)

## 1. Why even include a signature:
When:
- The request is already transported through HTTPS.
- The request already contains an Authorization header or some forms of token.

Both of the above mechanisms are implemented to protect API security, but none of them fully guarantees the <span style="color:#e5202a">integrity</span> of the request or that  the request is not <span style="color:#e5202a">replayable/repeatable</span> (pain to both hacker and tester :rofl:).

By using HTTPS, tampering can be prevented during transit but it cannot be assumed that the request was `not sniffed and modified by the attacker`:
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
Content-Length: 81
Authorization: Bearer 31337
Signature: keyId=key-heckintosh,created=1627309524,signature=Krn2pycuWCjeKMB9Cl402rujedZrVF/jKTwjUuTl5Ew=
Digest: SXlPjVeb52yWclhgo9/rDRYnekneXSerRPfUGr54UGM=
Content-Type: application/json; charset=utf-8
Connection: close

{"AccountName":"heckintosh","Version":"1.0.0"}
```

These elements together contribute to building the `Signature` (header) in the above example:
- `keyId`: A string for the server to look up the component they need to validate the signature. 
- `secretkey`: A secret key 
- `created`: Unix time on which the request is created.
- `Authorization`: a token for authentication (JWT typically but i'm lazy to generate one).
- `Digest`: B64 encoded body of the request.
- `signature`: This parameter is a b64 encoded digital signature. The client uses an algorithm and a <span style="color:#e5202a">sign pattern</span> (consists of a list of concatenated value that developers choose) to form a  <span style="color:#e5202a">signing string</span>. This <span style="color:#e5202a">signing string</span> is then signed with the secret key associated with keyId and the algorithm. The signature parameter is then set to the b64 of the signature.

These elements are combined through the following steps:
```python
    keyId = "key-heckintosh"
    secretkey = "cf1337cd-a133-1337-acac-a337bece1337"
    created = int(time.time())
    digest = base64.b64encode(request_body)
    auth = "31337"
    sign_pattern = "keyId = {}, digest = {}, created = {},  auth = {}".format(keyId, digest, created, auth)
    signature = HMAC256(sign_pattern, secret_key)
    Signature = "keyId = {}, created={}, signature={}".format(keyId, created, signature)
```


## 3. 

## 1. HTTP Requests in Signature

Digital signatures are widely used to provide authentication and integrity assurances without the need for shared secrets. They also do not require a round-trip in order to authenticate the client, and allow the integrity of a message to be verified independently of the transport (e.g. TLS). A server need only have an understanding of the key (e.g. through a mapping between the key being used to sign the content and the authorized entity) to verify that a message was signed by that entity.

When optionally combined with asymmetric keys associated with an identity, this specification can also enable authentication of a client and server with or without prior knowledge of each other.

## 1. Unsubscribe from irrelevant emails

Inbox-zero isn’t a new idea but it’s infinitely more difficult to achieve this if you’re bombarded with emails from random retailers offering coupons and one-in-a-lifetime deals you’re never going to use.

A simple way to de-clutter your inbox is to look at each email you receive from a subscription and if it’s not immediately relevant (or will be in the foreseeable future), just scroll to the bottom and hit that unsubscribe button. Over time you’ll receive less and less irrelevant emails and this will naturally translate into less stress in the back of your mind.

And for those subscriptions and newsletters that you do want to keep, Unroll.me is a great tool I’ve used to manage the amount of content I see in my inbox. It allows you to wrap all relevant subscriptions into a daily newsletter that you see once and can tackle at your own leisure (it even allows you to unsubscribe directly from their platform!)

## 2. Unfollow people on social media

As you progress through school, jobs, projects, and whatever else you devote your time to, you tend to meet a lot of people who you may add on Facebook, follow on Instagram, but never develop a real relationship with. These acquaintances bloat your feeds and may cause you to miss out on important things that happen to those in your life who do matter.

What I have done is unfollow (or mute) the people that I don’t spend time with in person or plan to in the future. This includes brands, groups, events or influencers who I don’t feel are genuinely inspiring me. The beauty of this is that you are freeing up more time and mental space to interact with the content and people who you truly do want to invest in.

If you don’t want to be dramatic but still want more manageable social media feeds, the mute feature does thankfully exist. This allows you to mute someone’s posts, stories, and other notifications without explicitly unfollowing them and not tarnishing your (probably nonexistent) relationship with them.

## 3. Take occasional social media purges

It’s no secret that social media messes with the reward circuitry in your brain. One of the best ways to see just how it works is to take a social media purge where you commit to not using it for a certain amount of time. I’ve been surprised at how reflexively I reach for my phone and even more surprised at the free time and mental clarity I have after a couple days of adjusting.

In the past I’ve experimented with social media detoxes ranging from days to weeks and have found that the best strategy to avoid the temptation is to just delete the apps and not re-download until your purge is over. Most of the time you have an urge to check something, it’s simply a reflex and you won’t follow through since downloading the app again will take time and you will have caught yourself by then.

Another strategy, courtesy of Kenton Prescott is to enact a recurring purge, where you keep your phone in airplane mode (or even Do Not Disturb) for some amount of hours a day, limiting the time you spend catching up on notifications. The idea is that everyone can wait a few hours for your attention, even in the case of emergencies.

## 4. Turn off notifications for non-essential things

This one is pretty simple, just turn off notifications for things that are not essential. Every time your phone or wearable buzzes, you’re losing precious mental bandwidth which can take up to 23 minutes to get back!

In similar fashion to the previous steps, this takes some time and conscious effort daily where you take note of all notifications you get, evaluate if each one is worth the time, and turn off as necessary.

## 5. Learn how to use built in tools

One of my favorite features on my phone is Do Not Disturb. It allows you to silence all non-critical notifications for an indefinite amount of time. This is what I use when I’m working on school work, personal projects, or even this article. On both iOS and Android, you’re given fairly granular control over what is considered critical so you can pick and choose what is worth the focus lost from a distraction.

{% include elements/figure.html image="https://cdn-images-1.medium.com/max/1000/0*MAeS-4fEc0Y7T4VB.jpg" caption="iOS" %}
{% include elements/figure.html image="https://cdn-images-1.medium.com/max/1000/0*nF_H2-8oTY7C0a54.png" caption="Android" %}

Apple and Google also fairly recently rolled out time management tools which allow the user to be restricted from certain applications after a given amount of use. This really helps to add an extra layer of discipline if you’re trying to build the habit of using your phone less.

Minimalism isn’t a philosophy that demands you to sell everything you own, wear the same outfit for the rest of your life, and live out of your van. Rather, it’s taking a hard look at everything in your life and determining whether something truly provides happiness for you. Digital Minimalism is a subset of this way of thinking and is a philosophy that has allowed me to work in tech and be an active participant of social media, but also maintain my own level of free thinking and choose what I focus on.

I hope this has helped at least one person out there better manage their digital engagement. When I was first starting my foray into this way of thinking, this documentary by Matt D'Avella really helped me understand what minimalism was all about and is something I’d recommend if you’d like to learn more!