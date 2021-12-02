---
layout: post
title: HackTheBox BountyHunter Write-up
---

<h2>Overview</h2>

BountyHunter is an easy-rated Linux machine on HackTheBox. It's running a website with an XML parser, which I can abuse with an XXE attack. In doing so, I'm able to read the contents of a
database file containing credentials which can be used to ssh in.

<h2>Initial Enumeration</h2>

Initial nmap scan reveals two ports open, ssh on 22 and an Apache website on 80.

```
┌──(kali㉿kali)-[~/…/Labs/htb/htb-active/temp]
└─$ sudo nmap -sC -sV --min-rate 10000 10.10.11.100          
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-01 08:58 GMT
Nmap scan report for 10.10.11.100
Host is up (0.040s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.47 seconds
```

<h2>"Bounty Hunters" website</h2>

Heading over to the website in my browser I'm greeted with this page:

![image](https://user-images.githubusercontent.com/44827973/144485752-7dfc04ad-3b30-4c88-b230-87825b0eaa3d.png)


Clicking "PORTAL" in the top right leads me to the message below.

![image](https://user-images.githubusercontent.com/44827973/144485841-e98ae5fb-ff69-4bd2-8530-63a379616eef.png)

Following the link, I find a submission form for reporting bug bounties.

![image](https://user-images.githubusercontent.com/44827973/144485922-9f121baa-8415-4190-a20e-123f452ecccc.png)

I put in some test values and when submitted, the page returns the same values. Nothing too special appears to be happening.

# INSERT BASIC TESTING SCREENSHOT HERE#

<h3>Revealing sensitive data via XXE attacks</h3>

I want to see if there's interesting in the POST request that can be abused. I fire up Burp Suite and intercept some test values:

![image](https://user-images.githubusercontent.com/44827973/144486504-dc51dfbf-6b33-42f6-a770-8d1757ef15c0.png)

The intercepted POST request has a single parameter, data. Instantly I recognise it as URL-encoded, due to the presence of %3D%3D which is URL-encoded "==" characters.

![image](https://user-images.githubusercontent.com/44827973/144486580-51b59c93-4f46-4d7b-9f46-79a23647b8f8.png)

I send the data to Burp's Decoder. First I URL-decode it, and I receive what looks like a base64-encoded string. What gives it away is the "=" characters, which sometimes pads the end of base64-encoded strings.
So then I base64-decode the URL-decoded data. You can see the results below.

![image](https://user-images.githubusercontent.com/44827973/144486896-cb908a70-54be-40c5-8a10-530d0282130c.png)

It looks like the data being sent to the web server is XML-formatted. Because the web server is likely to process XML data, I may be able to conduct an XXE attack.

An XML eXternal Entity (XXE) attack abuses the parsing of XML data by creation of a custom XML entity. These are called External entities because they are defined from outside of the Document Type Definition (DTD).
We can define an entity to contain the contents of a file.

I test this by following the XML example as per the [https://portswigger.net/web-security/xxe](XXE article on Portswigger).

Here is my payload to attempt to read the contents of /etc/passwd:

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "/etc/passwd"> ]>
		<bugreport>
		<title>1</title>
		<cwe>2</cwe>
		<cvss>3</cvss>
		<reward>&xxe;</reward>
</bugreport>
```
Using Burp's Decoder, I encode in the reverse order of which the data was decoded, i.e. base64 and then URL.

I substitute this data back into the data parameter of the intercepted POST request.

![image](https://user-images.githubusercontent.com/44827973/144491846-5d8aa284-8e38-408b-aece-0e4dbafe0e6a.png)

