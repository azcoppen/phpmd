#Server Security Software

*Prepared by Alex Cameron, 2014*

##OWASP
The Open Web Application Security Project (OWASP) is the central resource all developers and administrators should be familiar with, and consult regularly.

https://www.owasp.org/index.php/Main_Page

##Access Control
Remote network access onto a server relies on being able to connect to a port offering a networked service, such as SSH, FTP, SMTP, DNS, etc. If a port cannot be connected to, an intrusion cannot take place. Use **nmap** to scan a system for open ports.

```bash
apt-get install nmap
nmap -v www.example.com
```

####iptables
The first port of call for stop rogue connections is the UNIX system firewall, which should be switched on and denying all connections for anything other than what is permitted from specified IPs. In most cases, this should only be SSH, HTTP, and HTTPS.

```bash
# SSH only from a specific IP
iptables -A INPUT -i eth0 -p tcp -s 192.168.100.0/24 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
# Lock out after 4 failed attempts in 60 seconds
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent ! --rcheck --seconds 60 --hitcount 4 --name ssh --rsource -j ACCEPT
```

####VPN
If possible, the only connections that can gain system access should be required to come through a VPN only. For this, use **OpenVPN**:

https://openvpn.net/

```bash
apt-get install bridge-utils openvpn easy-rsa
nano /etc/network/interfaces
nano /etc/sysctl.conf #enable forwarding
make-cadir /etc/openvpn/easy-rsa
sudo nano /etc/openvpn/easy-rsa/vars
# create client certs
# create server scripts
nano  /etc/openvpn/server.conf 
```

*NB: Do NOT use PPTP.*

####SSH
To limit and police rogue SSH connections, use **fail2ban**:

> "Fail2ban scans log files (e.g. /var/log/apache/error_log) and bans
> IPs that show the malicious signs -- too many password failures,
> seeking for exploits, etc. Generally Fail2Ban is then used to update
> firewall rules to reject the IP addresses for a specified amount of
> time, although any arbitrary other action (e.g. sending an email)
> could also be configured. Out of the box Fail2Ban comes with filters
> for various services (apache, courier, ssh, etc)."

http://www.fail2ban.org/wiki/index.php/Main_Page

```bash
apt-get install fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
nano /etc/fail2ban/jail.local
service fail2ban restart
```
####Shellshock
Don't forget to test for it: CGI software (e.g. cPanel) uses bash.

```bash
curl https://shellshocker.net/shellshock_test.sh | bash
```

####Applications
To limit what specific programs can and cannot do, use **AppArmor**:

> "AppArmor ("Application Armor") is a Linux kernel security module
> released under the GNU General Public License. AppArmor allows the
> system administrator to associate with each program a security profile
> that restricts the capabilities of that program. It supplements the
> traditional Unix discretionary access control (DAC) model by providing
> mandatory access control (MAC)."

http://wiki.apparmor.net/index.php/Main_Page

```bash
apt-get install apparmor apparmor-profiles
apparmor_status
aa-complain /path/to/bin
aa-enforce /etc/apparmor.d/*
service apparmor reload
```

###Anti-Virus
Any files that are uploaded onto a server (e.g. as part of a web application), downloaded via wget/curl, or are just unknown need to be virus-scanned, as do outgoing emails. The first and only server-side anti-virus for Linux is **ClamAV**:

http://www.clamav.net/index.html

```bash
apt-get install clamav clamav-daemon
freshclam
clamscan --infected --remove --recursive /home
```

###Eavesdropping
Do not be fooled or deceived. Almost all internet raffic is sent in **plain text**, and is easily recorded by multiple types of malicious actor. All services originating or terminating at a server should be  secured with TLS (Transport Layer Security).
If you have an application that does not natively support SSL termination, you can use **stunnel** to create a virtual client-server "bridge" between machines that encrypted traffic can be sent and received over.

https://www.stunnel.org/index.html

```bash
apt-get install stunnel4
nano /etc/stunnel/stunnel.conf
# create certs
nano /etc/default/stunnel4
service stunnel4 restart
```

###Intrusion Detection (IDS)
An Intrusion Detection System is a server burglar alarm, and there are many different packages available. All act to detect unauthorised access and/or bad behaviour patterns on a server, and alert an administrator. They work by collecting details about your computer's filesystem and configuration. It then stores this information to reference and validate the current state of the system. If changes are found between the known-good state and the current state, it could be a sign that your security has been compromised.

####Snort

The best known is **Snort**:

> "Snort's open source network-based intrusion detection system (NIDS)
> has the ability to perform real-time traffic analysis and packet
> logging on Internet Protocol (IP) networks. Snort performs protocol
> analysis, content searching, and content matching. These basic
> services have many purposes including application-aware triggered
> quality of service, to de-prioritize bulk traffic when
> latency-sensitive applications are in use. The program can also be
> used to detect probes or attacks, including, but not limited to,
> operating system fingerprinting attempts, common gateway interface,
> buffer overflows, server message block probes, and stealth port
> scans."

https://www.snort.org/

```bash
apt-get install snort
mkdir /etc/snort
mkdir /etc/snort/rules
cp snort_inline-2.6.1.3/etc/* /etc/snort/
cp snort-2.6.1.3/etc/classification.config /etc/snort_inline/rules/
cp snort-2.6.1.3/etc/reference.config /etc/snort_inline/rules/
useradd snort -d /var/log/snort -s /bin/false -c SNORT_IDS
mkdir /var/log/snort
chown -R snort /var/log/snort
snort –u snort –c /etc/snort/snort.conf
```
*NB: Don't try and install Snort from source, unless you're a masochist who wants a day of frustration and disappointment.*

Snort is used with Pulled Pork (http://www.rivy.org/2013/03/updating-snort-rules-using-pulled-pork/), Barnyard2 (http://www.rivy.org/2013/03/building-barnyard2-from-source/), and Snorby (http://www.rivy.org/2013/03/installing-snorby/).

####OSSEC
A more friendly and automatic IDS is **OSSEC** (Open Source SECurity):

> "OSSEC is a free, open-source host-based intrusion detection system
> (HIDS). It performs log analysis, integrity checking, Windows registry
> monitoring, rootkit detection, time-based alerting, and active
> response.[jargon] It provides intrusion detection for most operating
> systems, including Linux, OpenBSD, FreeBSD, Mac OS X, Solaris and
> Windows. OSSEC has a centralized, cross-platform architecture allowing
> multiple systems to be easily monitored and managed."

http://www.ossec.net/

```bash
deb http://ossec.alienvault.com/repos/apt/debian wheezy main
apt-get install ossec-hids
nano /var/ossec/etc/ossec.conf
/var/ossec/bin/ossec-control restart
```

####Tripwire

Another approach is **Tripwire**, which works by creating encrypted signatures for all the files on a server and alerting you when the signatures have changed (e.g. malware spreading into HTML files).

> When first initialized, Open Source Tripwire scans the file system as
> directed by the administrator and stores information on each file
> scanned in a database. At a later date the same files are scanned and
> the results compared against the stored values in the database.
> Changes are reported to the user. Cryptographic hashes are employed to
> detect changes in a file without storing the entire contents of the
> file in the database.

http://sourceforge.net/projects/tripwire/

```bash
apt-get install tripwire
twadmin --create-polfile /etc/tripwire/twpol.txt
tripwire --init
```
####Tiger

The oldest UNIX IDS and auditing tool is **Tiger**, which can be compiled from source to check a system configuration (rather than logs etc):

http://www.nongnu.org/tiger/

```bash
wget http://download.savannah.gnu.org/releases/tiger/tiger-3.2.3.tar.gz
tar -xvf tiger-3.2.3.tar.gz && cd tiger* && ./configure && sudo make && sudo make install
tiger
```
####Also
Others include:
 - LIDS (http://en.wikipedia.org/wiki/Linux_Intrusion_Detection_System), 
 - SNARE (http://en.wikipedia.org/wiki/Snare_(software)), and 
 - AIDE (http://aide.sourceforge.net/).

###Rootkit Scanning
Rootkits are pieces of stealth software that are designed to be invisible backdoor programs installed onto a server that enable an intruder to acquire and maintain root access over it. They are typically installed immediately after a break-in.

####RKHunter

The first line of defense against a rootkit is **RKHunter**:

> "rkhunter (Rootkit Hunter) is a Unix-based tool that scans for
> rootkits, backdoors and possible local exploits. It does this by
> comparing SHA-1 hashes of important files with known good ones in
> online databases, searching for default directories (of rootkits),
> wrong permissions, hidden files, suspicious strings in kernel modules,
> and special tests for Linux and FreeBSD."

http://rkhunter.sourceforge.net/

```bash
apt-get install rkhunter
rkhunter --propupd
rkhunter --checkall
```
####CHKRootkit

The 2nd main option is a shell script called **chkrootkit**:

> "chkrootkit (Check Rootkit) is a common Unix-based program intended to
> help system administrators check their system for known rootkits. It
> is a shell script using common UNIX/Linux tools like the strings and
> grep commands to search core system programs for signatures and for
> comparing a traversal of the /proc filesystem with the output of the
> ps (process status) command to look for discrepancies."

http://www.chkrootkit.org/

```bash
apt-get install chkrootkit
chkrootkit
```

###Defensive HTTP
The first and only point for server entry is weak security in a web application. The #1 target being **Wordpress** of course, closely followed by Joomla, Drupal, admin panels (cPanel, Plesk etc), and custom login panels. 

```bash
ServerSignature Off # httpd.conf
expose_php = Off # php.ini or hhvm/server.ini
server_tokens off; # nginx.conf

```

```http
Strict-Transport-Security: max-age=60
X-content-type-options: nosniff
X-frame-options: SAMEORIGIN
X-xss-protection: 1; mode=block
```

Never allow sensitive files to be served through an HTTP server, and be mindful of the default mime-type (*text/plain* in Apache).

```js
  location ~ (config.php|app) {
    deny all;
  }

  location ~ \.(cache|db|log|po|pot|sql|razr)$ {
    deny all;
  }
  
  location ~ /\. {
  deny all;
  }
```

####SSL/TLS
There is no reason NOT to use SSL for any and all HTTP connections. Certificates can be generated using **OpenSSL** (1.0.1g or later to avoid *Heartbleed*), and all HTTP traffic should be diverted to the HTTPS/443 default.

*NB: SSL should use TLS 1.2 with AES256, with Perfect Forward Secrecy (ECDHE-RSA) Do NOT use MD5 or 3DES.* 

Cipher order:
```bash
EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS
```
http://en.wikipedia.org/wiki/Forward_secrecy#Perfect_forward_secrecy
https://www.digicert.com/ssl-support/ssl-enabling-perfect-forward-secrecy.htm

```bash
openssl version
openssl genrsa -des3 -out default.key.enc 2048
openssl req -new -key default.key.enc -out default.csr
openssl x509 -req -days 365 -in default.csr -signkey default.key.enc -out default.crt
openssl rsa -in default.key.enc -out default.key
```

####htpasswd
The first step is to inspect the server's HTTP response headers to determine what software it is running.

```bash
curl -X HEAD -i http://www.weareinteractive.ca
```
```http
HTTP/1.1 200 OK
Connection: keep-alive
Set-Cookie: __cfduid=d5ad319f86194ff91279c7d35fa66f9bb1416450282; expires=Fri, 20-Nov-15 02:24:42 GMT; path=/; domain=.weareinteractive.ca; HttpOnly
Set-Cookie: lang=fr; expires=Thu, 20-Nov-2014 03:24:42 GMT; path=/
X-Powered-By: PleskLin
Server: cloudflare-nginx
```
If you cannot inspect the headers, you cannot profile the target. Use **htpasswd** to require HTTP basic authentication on any area that is not public.

```bash
apt-get install apache2-dev apache2-utils
htpasswd -c .htpasswd newuser
```
```js
    location ^~ /admin-route/ {
        auth_basic "Protected Area";
        auth_basic_user_file /path/to/.htpasswd;
        try_files $uri $uri/ /index.php?$args;
    }
```
####mod_security

Along with **mod_evasive**, the lion of all web application security is Apache's **mod_security** module, which is a Web Application Firewall (WAF). It works by looking for suspicious patterns in GET and POST requests, and blocking them with a HTTP 406 error. Installing it can defeat up to 80% of attacks. 

*Rulesets can be downloaded from **OWASP**.*

Examples:
```http
GET /page.php?include=../../../../../../../../etc/passwd
POST ?foo=bar&image_file=danger.php
GET /login.php?username=admin'">DROP%20TABLE%20users--
```

> "ModSecurity™ is an open source, free web application firewall (WAF)
> Apache module. With over 70% of all attacks now carried out over the
> web application level, organizations need all the help they can get in
> making their systems secure. WAFs are deployed to establish an
> external security layer that increases security, detects and prevents
> attacks before they reach web applications. It provides protection
> from a range of attacks against web applications and allows for HTTP
> traffic monitoring and real-time analysis with little or no changes to
> existing infrastructure."

https://www.modsecurity.org/
https://github.com/SpiderLabs/ModSecurity
https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project

```bash
# Compile standalone module
git clone https://github.com/SpiderLabs/ModSecurity.git mod_security
cd mod_security
./autogen.sh
./configure --enable-standalone-module
make

# Now install NGINX
wget http://www.nginx.org/download/nginx-1.4.2.tar.gz
tar -xvpzf nginx-1.4.2.tar.gz
cd nginx-1.4.2
./configure --add-module=../mod_security/nginx/modsecurity
make
make install
```

```js
location / {
  ModSecurityEnabled on;
  ModSecurityConfig modsecurity.conf;
}
```
http://www.nginxtips.com/how-to-install-mod_security-on-nginx/

###Attack Tests
The industry term for vulnerability discovery and legal "hacking" is **penetration testing**. It requires *written agreement* from a target, or you're going to jail.

####Professional Setup

The default system used by engineers is **Kali Linux** (formerly *BackTrack*: https://www.kali.org/).

The best known tools are **Core Impact** (http://www.coresecurity.com/core-impact-pro) and **MetaSploit** (http://www.metasploit.com/).

####Other important tools

- Acunetix (WAS): https://www.acunetix.com/
- Aircrack-ng/Kismet (Wi-Fi): http://www.aircrack-ng.org/
- Burpsuite (WAS): http://portswigger.net/burp/
- Cain & Abel (ARP poisoning): http://www.oxid.it/cain.html
- Ettercap (MITM attacks): http://ettercap.github.io/ettercap/
- Hackbar (Firefox): https://addons.mozilla.org/en-US/firefox/addon/hackbar/
- John The Ripper (password cracking): http://www.openwall.com/john/
- Nessus (scanning): http://www.tenable.com/products/nessus
- Ratproxy (Proxying): https://code.google.com/p/ratproxy/
- Skipfish (Recon): https://code.google.com/p/skipfish/
- SQLMap (SQL injection): http://sqlmap.org/
- Tamper (Firefox): https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
- W3af (Auditing): http://w3af.org/
- Wapiti (WAS): http://wapiti.sourceforge.net/
- WebScarab (WAS): http://en.wikipedia.org/wiki/WebScarab
- Wfuzz (Brute-forcing): http://www.edge-security.com/wfuzz.php
- Zed Attack Proxy (WAS): https://code.google.com/p/zaproxy/

####WPScan
Special mention needs to be made of the main Wordpress vulnerability scanner **wpscan**, which is provided as a *rubygem*.

> "WPScan is a black box WordPress Security Scanner written in Ruby
> which attempts to find known security weaknesses within WordPress
> installations. Its intended use it to be for security professionals or
> WordPress administrators to asses the security posture of their
> WordPress installations."

```bash
git clone https://github.com/wpscanteam/wpscan.git
cd wpscan
sudo gem install bundler && bundle install --without test
ruby wpscan.rb --update
ruby wpstools.rb --check-local-vulnerable-files /var/www/wordpress/
ruby wpscan.rb --url www.target.com --enumerate
```

http://wpscan.org/
https://wpvulndb.com/
http://codex.wordpress.org/Hardening_WordPress

*For more comprehensive notes on hardening the waking security nightmare that is Wordpress, see the separate Wordpress security configuration guide.*

###Forensics
99% of stopping an attack is preventing it before it happens. But if it does, it needs to be detected. And if you can't detect it, you need to be able to discover what happened. See: https://forensics.cert.org/

####Logwatch
Logwatch does what it says on the tin: it watches your logs, and sends you a daily report digest on them.

```bash
apt-get install logwatch
nano /usr/share/logwatch/default.conf/logwatch.conf
```
http://sourceforge.net/projects/logwatch/files/

####PSAD
A nice fork of the Snort IDS is a set of 3 daemons that work together to form Ciberdyne PSAD, which also doubles as an IDS.

> "psad is a collection of three lightweight system daemons (two main
> daemons and one helper daemon) that run on Linux machines and analyze
> iptables log messages to detect port scans and other suspicious
> traffic. A typical deployment is to run psad on the iptables firewall
> where it has the fastest access to log data. "

http://cipherdyne.org/psad/

```bash
apt-get install psad
nano /etc/psad/psad.conf
psad -R
```

####SysDig
After it's all gone wrong, the most comprehensive digger in the open-source world is sysdig, a comparatively new package that performs deep analysis of log files and system changes, and can be used as a general-purpose problem hunting tool. It is particularly useful on *honeypot* systems.

> "Sysdig is open source, system-level exploration: capture system state
> and activity from a running Linux instance, then save, filter and
> analyze. Think of it as strace + tcpdump + lsof + awesome sauce. With
> a little Lua cherry on top."

http://www.sysdig.org/

```bash
curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -  
curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/stable/deb/draios.list  
apt-get update
apt-get install linux-headers-$(uname -r)
apt-get install sysdig
```

