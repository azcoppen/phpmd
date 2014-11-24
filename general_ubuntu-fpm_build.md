#PHP-FPM Server Build (Ubuntu 14)

You can use this file to rebuild more server instances. The values (usernames etc) are *examples only*.

####Create master user
``` bash
apt-get update
apt-get upgrade
groupadd dev-users
adduser site-dev
usermod -a -G www-data site-dev
usermod -m -d /var/www site-dev
sudo /usr/sbin/visudo
Add: dite-dev  ALL=(ALL:ALL) ALL
```
####Create individual users
``` bash
sudo su
useradd -d /var/www/repo dev-example 
usermod -a -G dev-users,www-data dev-group
passwd dev-example
```

####Create directories for subdomains
``` bash
cd /var/www
mkdir subdomainname logs ssl
chgrp -R www-data /var/www
```
####Add basic firewall rules
``` bash
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name ssh --rsource
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent ! --rcheck --seconds 60 --hitcount 4 --name ssh --rsource -j ACCEPT
iptables -A INPUT -p tcp -m state -m tcp --dport 443 --state NEW -j ACCEPT
iptables -A INPUT -p tcp -m state -m tcp --dport 80 --state NEW -j ACCEPT
```

####Test for Shellshock
``` bash
curl https://shellshocker.net/shellshock_test.sh | bash
```
####Add repos & remove Apache
``` bash
apt-get install software-properties-common
wget http://deb.erianna.com/gnugpg.key
apt-key add ./gnugpg.key
echo "deb http://deb.erianna.com precise main" > /etc/apt/sources.list.d/erianna.list
add-apt-repository ppa:ondrej/php5 #Latest PHP
add-apt-repository ppa:jon-severinsson/ffmpeg #Latest
apt-get remove --purge apache2
apt-get update
```
####Mass install the awesomeness
``` bash
apt-get -y --force-yes install fail2ban snort openvpn psad rkhunter chkrootkit nmap logwatch clamav clamav-daemon libxml2-dev libxml2-utils libaprutil1 libaprutil1-dev apache2-dev libdate-manip-perl apparmor apparmor-profiles tiger git zip unzip beanstalkd sox memcached supervisor make g++ libsndfile1-dev libpng++-dev libpng12-dev libboost-program-options-dev libopencv-dev libmcrypt-dev mcrypt libssl-dev libicu-dev libtidy-dev libaspell-dev libxml2 libxml2-dev libcurl4-openssl-dev libmcrypt-dev libmcrypt4 libjpeg-turbo8 libjpeg-turbo8-dev libpng12-dev libltdl-dev libreadline-dev autoconf automake build-essential libmagickcore-dev libass-dev  libfreetype6-dev libgpac-dev libsdl1.2-dev libtheora-dev libtool libvpx-dev libva-dev libvdpau-dev libvorbis-dev libx11-dev libxext-dev libxfixes-dev pkg-config texi2html zlib1g-dev yasm libmp3lame-dev libopus-dev libx264-dev librtmp-dev libopencore-amrnb-dev libspeex-dev libxvidcore-dev npm pound varnish nginx imagemagick mysql-server mysql-client poppler-utils default-jre libfaac-dev sphinxsearch gearman subversion haproxy GraphicsMagick redis-server redis-tools ffmpeg apache2-utils
```

####Update anti-virus definitions & refresh
``` bash
freshclam
apt-get update
apt-get upgrade
```
####Install the latest PHP build
``` bash
apt-get install php5=5.5.17+dfsg-2+deb.sury.org~trusty+1
```

####Install PHP-FPM, CLI, and extensions
``` bash
apt-get install php5-cli php5-common php5-curl php5-dbg php5-dev php5-gd php5-gmp php5-json php5-ldap php5-mysql php5-odbc php5-pgsql php5-pspell php5-readline php5-recode php5-sqlite php5-tidy php5-xmlrpc php5-xsl php-codesniffer php-doc php-http-request2 php5-enchant php5-fpm php5-gearman php5-geoip php5-imagick php5-intl php5-memcache php5-memcached php5-mongo php5-oauth php5-ps php5-redis phpunit php5-imap php5-mcrypt php5-xdebug
```

####Install Composer and NPM tools
``` bash
wget https://bootstrap.pypa.io/get-pip.py
pip install fabric
python get-pip.py
npm install -g bower grunt gulp
curl -sS https://getcomposer.org/installer | php
mv ./composer.phar /usr/bin/composer
apt-get update
apt-get upgrade
```

####Set up MySQL securely
``` bash
mysql_install_db
service mysql restart
/usr/bin/mysql_secure_installation
```

####Set up first MySQL databases
``` bash
mysql -u root -p
```
``` sql
CREATE DATABASE phpci;
CREATE DATABASE openfire;
CREATE USER 'phpci'@'localhost' IDENTIFIED BY 'strongpassword';
CREATE USER 'dev'@'localhost' IDENTIFIED BY 'strongpassword';
CREATE USER 'openfire'@'localhost' IDENTIFIED BY 'strongpassword';
GRANT ALL PRIVILEGES ON phpci.* TO 'phpci'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'dev'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'dev'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON openfire.* TO 'openfire'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

####Set up Openfire XMPP server
``` bash
wget -o openfire.deb http://www.igniterealtime.org/downloadServlet?filename=openfire/openfire_3.9.3_all.deb 
sudo dpkg --install openfire.deb
```
Admin panel is then available at http://www.domain.com:9090

####Set up CI Server & PHP Info
``` bash
cd /var/www/ci
composer create-project block8/phpci phpci --keep-vcs --no-dev
cd phpci
chmod +x ./console
console phpci:install
cd public
nano phpinfo.php > phpinfo();
wget http://phpsec.org/projects/phpsecinfo/phpsecinfo.zip
unzip phpsecinfo.zip
mv phpsecinfo-20070406 phpsecinfo
```

####Set up Laravel instances
For each dev dir:
``` bash
cd /var/www/subdomainname
composer create-project laravel/laravel laravel --prefer-dist
chmod -R 777 laravel/app/storage
cd laravel/public
nano phpinfo.php > phpinfo();
```

####Configure PHP settings & note log files
``` bash
nano /etc/php5/fpm/php.ini
nano /etc/php5/fpm/php-fpm.conf
nano /etc/php5/fpm/pool.d/www.conf
```

####Add password protection users
``` bash
htpasswd -c /var/www/.htpasswd ht-dev
```

#### Optional - mod_security for nginx source
``` bash
git clone https://github.com/SpiderLabs/ModSecurity.git mod_security
cd mod_security && ./autogen.sh && ./configure --enable-standalone-module && make
```

####Configure nginx master conf file
``` bash
nano /etc/nginx/conf/nginx.conf
```
``` js
    log_format  main  'fpm - $document_root$fastcgi_script_name - $remote_addr - $remote_user [$time_local] "$request" '
 '$status $body_bytes_sent "$http_referer" '
'"$http_user_agent" "$http_x_forwarded_for"';

 log_format extended '$remote_addr - $remote_user [$time_local]  '
 '"$request" $status $body_bytes_sent'
 ' $upstream_addr $upstream_status $upstream_response_time '
 '"$http_referer" "$http_user_agent" $request_time $http_x_uuid';
    
    gzip  on;
    etag on;
    proxy_buffer_size   128k;
    proxy_buffers   4 256k;
    proxy_busy_buffers_size   256k;
    
    auth_basic "Development Server"
    auth_basic_user_file /var/www/.htpasswd;
```
####Add nginx virtual hosts
``` bash
cd /etc/nginx/conf/conf.d
nano all_vhosts_global.conf #PASTE
```

####Example virtual host file
``` js

server {
    listen   80;
    server_name  dev.example.com    sub.otherdomain.com    sub2.anotherdomain.com;
    root        /var/www/vms/laravel/public;
    access_log  /var/www/vms/logs/access.log  main;
    error_log   /var/www/vms/logs/error.log  debug;
    
    location / {
        if ($request_method = OPTIONS ) {
            add_header Access-Control-Allow-Methods "GET, POST, HEAD, OPTIONS";
            add_header Access-Control-Allow-Origin "*";
            add_header 'Access-Control-Allow-Headers' 'DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type';
            return 200;
        }
        try_files $uri $uri/ /index.php?$args;
    }
    include all_vhosts_global.conf;  
}
```
####Fix errors and restart services
``` bash
chown -R www-data /var/www
chgrp -R www-data /var/lib/php5/ # php session files
service php5-fpm start
service nginx start
```
**NB: Most problems are down to /var/run/php5-fpm.sock being misconfigured somewhere or the permissions not set properly. **

####Test URLS
```
http://ci.website.com/__i.php # PHPInfo()
http://ci.website.com/ # set up CI
http://app.website.com/ # Laravel install
```