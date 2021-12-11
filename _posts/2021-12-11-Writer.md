---
layout: post
title: HackTheBox Writer Write-up
---

<h2>Overview</h2>

Writer is a medium-rated Linux machine on HackTheBox. I find a website vulnerable to SQL injection, which allows file reading of a file containing credentials.
I'm able to connect to SMB using these credentials, and upload a modified manager.py containing a reverse shell, granting me shell as www-data. Following this, a number of privilege escalations are made.
As www-data, I first discover credentials to the MySQL database, which contains the user kyle's hashed password. Cracking it allows me to ssh in as kyle. As kyle, I discover I'm in a group with privileges to modify the /etc/postfix/disclaimer file, and
I inject a reverse shell command which triggers a reverse shell as john when I send an email to john. As john, I find I'm in a group with write access to /etc/apt/apt.conf.d. I create an apt configuration file with reverse shell code, and get a reverse shell as root.

<!--more-->

<h2>Initial Enumeration</h2>

<h2>Website on port 80</h2>

Heading over to the website, it looks like a writer's professional website.

![image](https://user-images.githubusercontent.com/44827973/145673392-5633e91e-1888-4b70-8b29-826a26db3d28.png)

Clicking available links doesn't get me far, so I run a directory scan.

Feroxbuster scan reveals the "/administrative" URL.

![image](https://user-images.githubusercontent.com/44827973/145673425-fb02819c-d8c4-4ceb-9107-0f411a0fea95.png)

It takes me to a login page.

![image](https://user-images.githubusercontent.com/44827973/145673451-33d47b55-a872-4fc0-b874-f80bc45e1687.png)

I test a few simple credentials without luck.

<h2>SQL Injection</h2>

Testing a SQL injection payload, I'm able to bypass the login panel and log in to a dashboard.

`admin'; -- -`

![image](https://user-images.githubusercontent.com/44827973/145673485-1e012369-9668-4f1d-a6e5-e72862cdd746.png)

There isn't much to do here. I'm able to add stories, but not a whole lot else.

Going back to the SQL injection, I want to see if I can gather more information.

I intercept a login request with Burp, and save the output to a file. I can use SQLmap against this request to automate SQL injection.

![image](https://user-images.githubusercontent.com/44827973/145673578-aebcd1d4-2383-4289-8469-7297c1c43ec5.png)

I specify the request file and the parameter to test for SQL injection, which is `uname`. It confirms the uname parameter is vulnerable, and that the SQL server is MySQL.

![image](https://user-images.githubusercontent.com/44827973/145673579-48632376-5ee0-4907-9f19-155a5977badf.png)

I tried sqlmap -r post.req -p uname --os-shell, but the sql service user is unable to write to any locations.

Instead, I check what privileges are available to the sql service.

![image](https://user-images.githubusercontent.com/44827973/145673625-8212b05e-e2db-43ad-a863-c12c16a9c8a0.png)

We have "FILE" privileges. Although I'm unable to write to any locations where I could place a PHP shell, maybe I can read some sensitive files.

First I check `/etc/passwd` to see what users exist on the box.

`sqlmap -r sqlmap-post.txt -p uname --file-read=/etc/passwd`

SQLmap writes the output to `/home/kali/.local/share/sqlmap/output/writer.htb/files/_etc_passwd`.

![image](https://user-images.githubusercontent.com/44827973/145673707-205c2779-2007-45b6-8fc9-a6c5e430c2bb.png)

As we can see, there are two users: kyle and john.




  File read
    smb credentials in "/var/www/writer.htb/writer/__init__.py"
    
SMB access as kyle
  updating manager.py with python reverse shell
 
Shell as www-data
  running linpeas reveals MySQL creds
  enumerating databases reveals kyle's hashed password
  cracking the hash gives password. SSH in
  
Shell as kyle
  check groups
  check files belonging to the group
  modify /etc/postfix/disclaimer with a reverse shell
  get a reverse shell as john + read john's ssh key

Shell as john
  check groups again
  check files belonging to the group
  write a malicious apt conf file to give reverse shell
  get a reverse shell as root
