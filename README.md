#ESAPI
---
OWASP（Open Web Application Security Project）是一个非盈利性组织，供有关计算机和互联网应用程序的公正、实际、有成本效益的信息

ESAPI (OWASP企业安全应用程序接口)是一个免费、开源的、网页应用程序安全控件库，它使程序员能够更容易写出更低风险的程序。ESAPI接口库被设计来使程序员能够更容易的在现有的程序中引入安全因素。

###Requirements

要PHP 5.3.3以上的版本;
php xml扩展模块;

###Installation

ESAPI修改后的版本遵循psr-4
svn https://svn***/incubator/

###Example

##### 初始化组建
```
<?php
require '/path/autoload.php';
ESAPI::init('/path/ESAPI.xml');
```
####Encoder

* 过滤js代码
```
<?php
$js = "<script>alert('1') </script>;";
$clean_js= ESAPI::getEncoder()->encodeForHTML($js)
echo $js;//html页面会弹出1
echo $clean_js;//&lt;script&gt;alert&#x28;&#x27;1&#x27;&#x29; &lt;&#x2f;script&gt;&#x3b;
```
* 过滤sql
```
<?php
use Wast\Codecs\MySQLCodec;
$sql = "select * from user where username='" . $username . "'"; 
$dity_username = $_GET['username'];//fake abc' or '1
$clean_username = ESAPI::getEncoder()->encodeForSQL(new MySQLCodec(), $dity_username);
echo $clean_username;//1
```
####Validator
* 验证是否是某个范围的整数
```
<?php
$input = 7;
ESAPI::getValidator()->isValidInteger('validate context', $input, 1, 10, false);//false
```
* 验证邮箱是否合法
```
<?php
$input = "test@sian.com";
// Email 的正则匹配在配置文件ESAPI.xml中 
// <regexp name="Email" value="^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[a-zA-Z]{2,4}$" />
ESAPI::getValidator()->isValidInput('validate email', $input, 'Email', 50, $false);//true
```
####Executor
* 执行命令行
```
<?php
//allowed executables config from ESAPI.xml
//  <ExecutorUnix>
//    <WorkingDirectory>/tmp</WorkingDirectory>
//    <ApprovedExecutables>
//      <command>/bin/dash</command>
//      <command>/usr/bin/sudo</command>
//    </ApprovedExecutables>
//  </ExecutorUnix>
$input = 7;
ESAPI::getExecutor()->executeSystemCommandLonghand('/bin/dash', array("-c", "'ls /'"), '/tmp',  false);
```
####Randomizer

* 生成随机文件名
```
<?php
$clean_js= ESAPI::getRandomizer()->getRandomFilename('jpg');//生16为字符的图片名称
```
####Sanitizer

* HTMLPurifier
```
<?php
$html = "<div><span>123</div>";
$html_purifier= ESAPI::getSanitizer()->getSanitizedHTML('jpg'， $html);
echo $html_purifier;//<div><span>123</span></div>

$html = 'Test.<script>alert(document.cookie)</script>';
$html_purifier= ESAPI::getSanitizer()->getSanitizedHTML('remove xss html'， $html);
echo $html_purifier;//Test.
```
* 过滤url
```
<?php
$url = "http:errorurl";
$url_purifier= ESAPI::getSanitizer()->getSanitizedURL('invalid url'， $url);
echo $url_purifier;//返回空

$url = "https://github.com";
$url_purifier= ESAPI::getSanitizer()->getSanitizedURL('valid url'， $url);
echo $url_purifier;//https://github.com
```
####HttpUtilities

* 生成CSRF token
```
<?php
ESAPI::getHTTPUtilities()->setCSRFToken();

//other page
$token = ESAPI::getHTTPUtilities()->getCSRFToken();
```

###Docmentation
see [http://owasp-esapi-php.googlecode.com/svn/trunk_doc/latest/index.html](http://owasp-esapi-php.googlecode.com/svn/trunk_doc/latest/index.html)
