#Badass CentOS - AC
The "Sombrero"configuration: a product of British-American Engineering efforts and a lot of coffee.

## Step 1: Create sudo user to use server as
``` bash
adduser operation
passwd operation
sudo /usr/sbin/visudo
Add: operation    ALL=(ALL:ALL) ALL -> save/wq!
groupadd www-data
usermod -a -G www-data operation
chgrp -R www-data /var/www
usermod -m -d /var/www operation
```

## Step 2: Log back in and update OS
``` bash
sudo su
yum update
yum upgrade
cat /etc/redhat-release --> COS 6.5
```

## Step 3: Configure SSH and basic firewall rules
``` bash
nano /etc/ssh/sshd_config
service sshd restart
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name ssh --rsource
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent ! --rcheck --seconds 60 --hitcount 4 --name ssh --rsource -j ACCEPT
iptables -A INPUT -p tcp -m state -m tcp --dport 443 --state NEW -j ACCEPT
iptables -A INPUT -p tcp -m state -m tcp --dport 80 --state NEW -j ACCEPT
```
See: http://wiki.centos.org/HowTos/Network/SecuringSSH

## Step 4: Install security software
####Test for Bash/OpenSSL vulnerabilities
``` bash
curl https://shellshocker.net/shellshock_test.sh | bash
openssl version (Heartbleed is 1.0.1)
```
####Install repos
``` bash
rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm #general sec EPEL
rpm -Uvh http://www5.atomicorp.com/channels/ossec/centos/6/x86_64/RPMS/ossec-release-1.0-2.el6.art.noarch.rpm #OSSEC
```
#### Install Atom repo
``` bash
wget http://www.atomicrocketturtle.com/RPM-GPG-KEY.art.txt
rpm –import RPM-GPG-KEY.art.txt
wget http://www.atomicorp.com/installers/atomic.sh
sh atomic.sh
```
####Install Tiger
``` bash
wget http://download.savannah.gnu.org/releases/tiger/tiger-3.2.3.tar.gz
tar -xvf tiger-3.2.3.tar.gz && cd tiger* && ./configure && sudo make && sudo make install
```
####Install all, and sysdig
``` bash
yum install fail2ban snort openvpn rkhunter logwatch tripwire chkrootkit ossec-hids ossec-hids-server clamav clamd
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash # Sysdig
```
Can also use apparmor: http://wiki.apparmor.net/index.php/Main_Page

##Step 5: Install basic libraries and utilities
####Add RPMForge
``` bash
rpm --import http://apt.sw.be/RPM-GPG-KEY.dag.txt
rpm -Uvh http://packages.sw.be/rpmforge-release/rpmforge-release-0.5.2-2.el6.rf.x86_64.rpm
```

####Core programs
``` bash
yum install git zip unzip mcrypt subversion make g++-c++ boost java-1.6.0-openjdk autoconf automake ruby rubygems opencv nginx nginx-debuginfo
```

####Image editing support
``` bash
yum install libjpeg-devel libpng-devel libsndfile-devel freetype freetype-devel ImageMagick ImageMagick-devel GraphicsMagick GraphicsMagick-devel
```


####Databases and queuing
``` bash
yum install mysql-server mysql-client redis postgresql beanstalkd memcached supervisor gearmand
```

####Advanced dev
``` bash
yum install yasm texi2html gstreamer poppler-utils npm varnish haproxy sphinx icu aspell readline libtool nasm
```

####Libraries
``` bash
yum install libxml2-devel httpd-devel apr-devel apr-util-devel perl-libxml-perl libmcrypt-devel curl-devel boost-devel pcre-devel fontconfig-devel sqlite-devel ruby-rdoc ruby-devel java-1.6.0-openjdk-devel opencv-devel libtool-ltdl libtool-ltdl-devel openssl-devel libicu-devel aspell-devel readline-devel libsphinxclient libsphinxclient-devel
```

####Audio/Video support
``` bash
yum install sox libass libass-devel zlib* libtheora libtheora-devel theora-tools libvpx libvpx-devel libvpx-utils libvorbis libvorbis-devel vorbis-tools libXfixes libXfixes-devel speex speex-tools speex-devel lame lame-devel flac-devel libmad libmad-devel twolame twolame-devel id3lib id3lib-devel x264 x264-devel flvtool2 rtmpdump librtmp librtmp-devel faac faac-devel amrnb amrnb-devel xvidcore xvidcore-devel libva libva-devel libvdpau libvdpau-devel ffmpeg ffmpeg-devel
```

##Step 6: Install latest PHP
``` bash
rpm -Uvh https://mirror.webtatic.com/yum/el6/latest.rpm
yum install php55w php55w-bcmath php55w-cli php55w-common php55w-dba php55w-devel php55w-fpm php55w-gd php55w-imap php55w-intl php55w-ldap php55w-mbstring php55w-mcrypt php55w-mysql php55w-opcache php55w-pdo php55w-pear php55w-pgsql php55w-process php55w-pspell php55w-recode php55w-soap php55w-tidy php55w-xml php55w-xmlrpc php55w-pecl-gearman php55w-pecl-geoip php55w-pecl-imagick php55w-pecl-imagick-devel php55w-pecl-memcache php55w-pecl-redis php55w-pecl-xdebug
```
##Step 7: Configure web tools
####Install pip and NPM tools
``` bash
wget https://bootstrap.pypa.io/get-pip.py
pip install fabric
python get-pip.py
npm install bower grunt gulp
```
####Install Composer & PHP Unit
``` bash
curl -sS https://getcomposer.org/installer | php
mv ./composer.phar /usr/bin/composer
yum install php-phpunit-PHPUnit
```
#### Optional - mod_security for nginx source
``` bash
git clone https://github.com/SpiderLabs/ModSecurity.git mod_security
cd mod_security && ./autogen.sh && ./configure --enable-standalone-module && make
```
####Install headless browser - 500MB!
``` bash
wget http://downloads.sourceforge.net/project/wkhtmltopdf/0.12.1/wkhtmltox-0.12.1_linux-centos6-amd64.rpm
rpm -ivh wkhtmltox-0.12.1_linux-centos6-amd64.rpm
yum install fontconfig libXrender libXext '*fonts*' 
```
####Install PhantomJS
``` bash
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-1.9.7-linux-x86_64.tar.bz2 && tar jxf phantomjs-1.9.7-linux-x86_64.tar.bz2
cd phantomjs-1.9.7-linux-x86_64 && cp bin/phantomjs /usr/bin/phantomjs
```

##Step 8: Set up database
####Secure setup for MySQL
``` bash
mysql_install_db
service mysqld start
/usr/bin/mysql_secure_installation
mysql -u root -p
```
####Add databases and users for PHPCI and main site
``` sql
CREATE database phpci;
CREATE database dbname;
CREATE USER 'phpci'@'localhost' IDENTIFIED BY 'strongpassword';
CREATE USER 'dbuser'@'localhost' IDENTIFIED BY 'strongpassword';
GRANT ALL PRIVILEGES ON phpci.* TO 'phpci'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON dbname.* TO 'dbname'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

##Step 9: Configure PHP
``` bash
nano /etc/php.ini
```
####Lock down php.ini
``` ini
expose_php = Off
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source #(this screws a lot of apps)
memory_limit = 512M
display_errors = On 
cgi.fix_pathinfo=0
allow_url_fopen = Off #(this screws composer)
date.timezone =	America/Montreal
mail.add_x_header = Off
session.save_path = /tmp
session.name = SESS
```
####Edit the PHP-FPM configuration
``` bash
nano /etc/php-fpm.d/www.conf
FPM error file: /var/log/php-fpm/error.log
```
``` ini
listen = /var/run/php5-fpm.sock
listen.owner = nobody
listen.group = www-data
listen.mode = 0660
user = nginx
group = www-data
pm.status_path = /status
ping.path = /ping
ping.response = pong
catch_workers_output = yes
```
``` bash
service php-fpm restart
```
##Step 10: Set up sites with Git repos + SSL
####Password protect the whole server
``` bash
cd /var/www
htpasswd -c /var/www/.htpasswd htuser
mkdir default mainsite pma
```
####Set up PHPCI as the default site
``` bash
cd default
mkdir logs ssl www
cd www
git init
composer create-project block8/phpci ci --keep-vcs --no-dev
cd ci
chmod +x ./console
console phpci:install
cd ../ssl
openssl genrsa -des3 -out default.key.enc 2048
openssl req -new -key default.key.enc -out default.csr
openssl x509 -req -days 365 -in default.csr -signkey default.key.enc -out default.crt
openssl rsa -in default.key.enc -out default.key
```
####Add phpMyAdmin subdomain with PHPSecInfo
``` bash
cd pma
mkdir logs ssl www
cd www
wget http://downloads.sourceforge.net/project/phpmyadmin/phpMyAdmin/4.2.9.1/phpMyAdmin-4.2.9.1-all-languages.zip?r=http%3A%2F%2Fwww.phpmyadmin.net%2Fhome_page%2Fdownloads.php&ts=1412884828&use_mirror=iweb 
mv "phpMyAdmin-4.2.9.1-all-languages.zip?r=http:%2F%2Fwww.phpmyadmin.net%2Fhome_page%2Fdownloads.php" pma.zip && unzip pma.zip
cd phpMyAdmin-4.2.9.1-all-languages
cp -R *  ../ && cd ../ && rm -rf phpMyAdmin-4.2.9.1-all-languages pma.zip
wget http://phpsec.org/projects/phpsecinfo/phpsecinfo.zip && unzip phpsecinfo.zip && mv phpsecinfo-20070406 phpsecinfo
```
####Add the main site
``` bash
cd elevent
mkdir logs ssl www
cd www
git init
cd ../ssl
openssl genrsa -des3 -out site.key.enc 2048
openssl req -new -key site.key.enc -out site.csr
openssl x509 -req -days 365 -in site.csr -signkey site.key.enc -out site.crt
openssl rsa -in site.key.enc -out site.key
cat elevent.crt site.key > site.pem
chgrp -R www-data /var/www
```

##Step 11: Configure nginx
####Create user for the web server
``` bash
usermod -a -G www-data nginx
chown -R nginx /var/www
chgrp -R www-data /var/lib/php/ # php session files
```
####Edit the main nginx config file
``` bash
nano /etc/nginx/nginx.conf
```
``` js
gzip  on;
etag on;
proxy_buffer_size   128k;
proxy_buffers   4 256k;
proxy_busy_buffers_size   256k;
auth_basic "Dev Server";
auth_basic_user_file /var/www/.htpasswd;
```
####Add virtual hosts with SSL
``` bash
nano /etc/nginx/all_vhosts_global.conf (PASTE)
nano /etc/nginx/conf.d/default.conf (PASTE)
nano /var/www/default/www/public/__i.php > <?php phpinfo(); ?>
service php-fpm restart
service nginx restart

##### if you get a 502 error on reload with no errors, it's a permissions error on the .sock file: do chmod go+rw /var/run/php5-fpm.sock

cp /etc/nginx/conf.d/pma.conf (EDIT/PASTE)
cp /etc/nginx/conf.d/elevent.conf (EDIT/PASTE)
service nginx restart
nano /etc/nginx/ssl/site.com.crt
nano /etc/nginx/ssl/site.ca.crt
nano /etc/nginx/ssl/site.key
```




