#Ubuntu Configuration
This setup file is applicable to both servers: development and production. Both are set up as mirrors of each other. Both run Ubuntu 14 and are set up to use Nginx, PHP-FPM 5.6 (OpCache) and MySQL. They are also loaded with many other tools, such as Redis, Memcached, Ruby, Varnish, HAProxy, FFMPEG, Beanstalkd, Postgres, Composer, NPM tools (Grunt, Gulp etc).

##Logging in
Each subdomain has its own UNIX user, and there's a super-user. Just SSH in via terminal or SFTP. The server is loaded with intrusion detection software (IDS), so you can easily get banned.
#####Log in to the dev server as the sudo user:
``` bash
ssh brand-dev@dev.example.com
```
#####Log in to the production server just as the UNIX user for the VMS:
``` bash
ssh prod-account@production.example.com
```
##What's installed?
``` bash
dpkg --get-selections | grep -v deinstall
dpkg --get-selections | grep -v deinstall > list.txt # send it to a file print out
```

##To update all the server software
Log in with SSH as the super user **brand-dev** or **prod-account**.
``` bash
sudo su
apt-get update
apt-get upgrade
freshclam #update anti-virus
composer self-update
```
For each repo installed in /var/www/< site >
``` bash
composer update -vvv
```
## Is it running?
####To check for the process itself:
``` bash
ps -el | grep nginx
ps -aux | grep fpm
```
####Kill a whole family of processes
``` bash
sudo su
pkill php-fpm
```
####What's listening on port X?
``` bash
netstat -tulpn | grep :80
```
##Starting and stopping services
All the service files are in /etc/init.d. Many don't give debug output if they fail.
``` bash
sudo su
service php5-fpm restart
service nginx reload
service openfire start
```
##Add a firewall rule
All the service files are in /etc/init.d. Many don't give debug output if they fail.
``` bash
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name ssh --rsource #SSH
iptables -A INPUT -p tcp -m state -m tcp --dport 443 --state NEW -j ACCEPT # HTTPS
iptables -A INPUT -p tcp -m state -m tcp --dport 80 --state NEW -j ACCEPT # HTTP
iptables reload|restart
```
## To deploy the latest changes
You have 2 options, neither of which involve FTP or SFTP.
####1. Use the PHPCI deployment tool.
http://ci.nightpost.com
####2. Log in and do a Git PULL
``` bash
sudo su
cd /var/www/< site >/
git pull origin master
```
*if you get errors about uncommitted changes, use: *
``` bash
git stash
```
## Checking log files
``` bash
tail -f /var/www/< subdomain >/logs/subdomain.error.log
tail -f /var/log/nginx/error.log
tail -f /var/log/php5-fpm.log
tail -f /var/log/php5-fpm.debug.log
```
## Change PHP configuration
PHP 5.6 is installed with OpCache and Fast Process Manager (http://php-fpm.org/) through unix://var/run/php5-fpm.sock. Nginx proxies PHP requests using FastCGI to a pool of PHP workers. It can be restarted independently of the web server without affecting it.
``` bash
nano /etc/php5/fpm/php.ini
nano /etc/php5/fpm/conf.d/somefile.ini
nano /etc/php5/fpm/pool.d/www.conf
```
**Important:** Always restart the PHP-FPM service after changes and check the error file if something's gone wrong (e.g. Nginx 502 error).
``` bash
service php5-fpm restart
tail /var/log/php5-fpm.log
tail /var/log/php5-fpm.debug.log
```

##Password protect a path or folder
Nginx supports htpasswd protection, and also allows you to protect virtual paths.
``` bash
apt-get install apache2-utils
htpasswd -c /path/to/.htpasswd usernametologinwith
```
Then in Nginx, add:
``` js
    location ^~ /admin-route/ {
        auth_basic "Protected Area";
        auth_basic_user_file /path/to/.htpasswd;
        try_files $uri $uri/ /index.php?$args;
    }
```
##Change web server configuration
Nginx uses files that have a JSON-like syntax, and is completely separate from PHP. You can reload it instead of restarting it, and it can easily handle SSL. Although it uses .htpasswd, It ignores .htaccess files, and uses a URL scheme, like so:
``` js
try_files $uri $uri/ /index.php?$args;
```
####Nginx master file
``` bash
nano /etc/nginx/conf/nginx.conf
```
**Important: this file contains the details of the HTTP Basic Authentication for the whole server. Comment out and reload nginx to remove it.**

####Settings for all virtual hosts
``` bash
nano /etc/nginx/conf/all_vhosts_global.conf
```
####Individual sites
``` bash
nano /etc/nginx/conf/conf.d/subdomain.conf
```
**Important:** You don't need to restart nginx. Just reload it.
``` bash
service nginx reload #BETTER
service nginx restart
```
####Example virtual host file
``` js

server {
    listen   80;
    server_name  dev.example.com    sub.otherdomain.com    sub2.anotherdomain.com;
    root        /var/www/site/laravel/public;
    access_log  /var/www/site/logs/access.log  main;
    error_log   /var/www/site/logs/error.log  debug;
    
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
##Generate self-signed SSL certificates
These obviously need to verified by a third-party, but are good enough for security. They should also be set up with Perfect Forward Secrecy (http://en.wikipedia.org/wiki/Forward_secrecy#Perfect_forward_secrecy)
```
openssl genrsa -des3 -out default.key.enc 2048
openssl req -new -key default.key.enc -out default.csr
openssl x509 -req -days 365 -in default.csr -signkey default.key.enc -out default.crt
openssl rsa -in default.key.enc -out default.key
```
####SSL ciphers for forward secrecy
```
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS";
```

## Subdomain setup
Each subdomain has 3 folders:

* Application or htdocs folder (www)
* logs
* ssl
``` bash
tail -f /var/www/< subdomain >/logs/subdomain.error.log
tail -f /var/log/nginx/error.log
tail -f /var/log/php5-fpm.log
tail -f /var/log/php5-fpm.debug.log
```
####Set up a Laravel project
``` bash
composer create-project laravel/laravel laravel --prefer-dist
chmod -R 777 laravel/app/storage
```
####Set up a PHPCI instance
``` bash
composer create-project block8/phpci phpci --keep-vcs --no-dev
cd phpci
chmod +x ./console
console phpci:install
```
####Set up a Beanstalk monitor console
``` bash
composer create-project ptrofimov/beanstalk_console -s dev beanstalk
nano config.php
chmod 777 storage.json
```
####Set up a Wordpress install
``` bash
composer create-project roots/bedrock wordpress
mv .env.example .env
nano .env
```
