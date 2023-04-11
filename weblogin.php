<?php
// bzlogin.php
//
// Copyright (c) 1993-2023 Tim Riker
//
// This package is free software;  you can redistribute it and/or
// modify it under the terms of the license found in the file
// named COPYING that should have accompanied this file.
//
// THIS PACKAGE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.

// Weblogin settings
$config = Array(
  // Used for checking for cross-site form submission. Should contain the
  // full domain name of the site hosting the weblogin.php script.
  'ourdomain' => $_SERVER['SERVER_NAME'],
);

define('IN_PHPBB', true);
$phpbb_root_path = '../../forums.bzflag.org/htdocs/';
$phpEx = 'php';
require($phpbb_root_path . 'includes/startup.' . $phpEx);
require($phpbb_root_path . 'phpbb/class_loader.' . $phpEx);
$phpbb_class_loader = new \phpbb\class_loader('phpbb\\', "{$phpbb_root_path}phpbb/", $phpEx);
$phpbb_class_loader->register();
$phpbb_config_php_file = new \phpbb\config_php_file($phpbb_root_path, $phpEx);
extract($phpbb_config_php_file->get_all());
@define('PHPBB_ENVIRONMENT', 'production');
$phpbb_container_builder = new \phpbb\di\container_builder($phpbb_root_path, $phpEx);
$phpbb_container = $phpbb_container_builder->with_config($phpbb_config_php_file)->get_container();
$phpbb_container->get('request')->enable_super_globals();
include($phpbb_root_path.'includes/functions.'.$phpEx);
include($phpbb_root_path.'includes/functions_compatibility.'.$phpEx);
include($phpbb_root_path.'includes/utf/utf_tools.'.$phpEx);

include('listdb.class.php');

// define dbhost/dbuname/dbpass/dbname here
// NOTE it's .php so folks can't read the source
include('/etc/bzflag/serversettings.php');

function dumpPageHeader () {

  # tell the proxies not to cache
  header('Cache-Control: no-cache');
  header('Pragma: no-cache');
  header('Content-type: text/html');

?><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
"http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
  <title>BZFlag Weblogin</title>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <link rel="stylesheet" href="css/weblogin.css">
  <link href="https://www.bzflag.org/favicon.ico" rel="shortcut icon">
</head>
<body>
  <div id="container">
    <div id="header">
      <img src="/images/webauth_logo.png" width="184" height="130" alt="">
      <h1>BZFlag Weblogin</h1>
    </div>
    <div id="main">
<?php
}

function dumpPageFooter () {
?>
    </div>
    <div id="footer">copyright &copy; 1993-2023 <a href="//wiki.bzflag.org/Tim_Riker">Tim Riker</a></div>
  </div>
</body>
</html>
<?php
}

function action_weblogin() {
  global $db;

  if ( array_key_exists("url", $_REQUEST) )
    $URL =  $_REQUEST['url'];
  else
    die ('ERROR, you must pass in a URL value');

  // Generate and store a session key
  $sessionKey = bin2hex(random_bytes(32));
  $_SESSION['webloginformkey'] = $sessionKey;

  // Parse the return URL
  $parsedURL = parse_url($URL);

  // If the URL fails to parse, we won't have a host
  if (!isset($parsedURL["host"]))
    die ('ERROR, you must pass in a URL value');

  foreach($_COOKIE as $cookiekey => $cookievalue) {
    if (substr($cookiekey, -3) === 'wlu' || substr($cookiekey, -3) === 'wlk') {
      setcookie($cookiekey, '', time()-172800);
      unset($_COOKIE[$cookiekey]);
    }
  }

  /*$hostkey = md5($parsedURL["host"]);

  $wlu = $hostkey.'wlu';
  $wlk = $hostkey.'wlk';

  if (isset($_COOKIE[$wlu]) && isset($_COOKIE[$wlk])) {
    // try autologin
    $uid = $_COOKIE[$wlu];

    $player = $db->getActiveForumUserByUserID($uid);

    if ($player && md5($parsedURL['host']).$player['user_password'] === $_COOKIE[$wlk]) {
      $token = random_int(0, 2147483647);
      $nameport = $parsedURL['host'];
      if (!empty($parsedURL['port']) {
        $nameport .= ':'.$parsedURL['port'];
      }
      $db->setTokenInformationByUserID($uid, $token, $nameport);
      if (true) {
        header('location: ' . str_replace(Array('%TOKEN%', '%USERNAME%'), Array(urlencode($token), urlencode($player['username'])), $URL));
        return;
      }
    }
  }
  */

  dumpPageHeader();
?>
      <div id="information">
        The website <b><?php echo htmlentities($parsedURL['host']); ?></b> is requesting a login using your BZFlag global login.<br>
        Please provide your username and password on this form.<br>
        Your password will <b>NOT</b> be sent to the requesting site.
      </div>

      <form action="<?php echo $_SERVER['SCRIPT_NAME']; ?>" method="POST">
        <div id="form">
          <input type="hidden" name="url" value="<?php echo htmlentities($URL); ?>">
          <input type="hidden" name="action" value="webvalidate">
          <input type="hidden" name="key" value="<?php echo htmlentities($sessionKey); ?>">
          <label id="usernamelabel">Username: <input name="username" id="username"></label>
          <label id="passwordlabel">Password: <input type="password" name="password" id="password"></label>
          <?php /*<label id="rememberlabel"><input type="checkbox" name="remember" id="remember"> Automatically login when going to <b><?php echo htmlentities($parsedURL['host']); ?></b></label>*/ ?>
          <label id="loginlabel"><input type="submit" id="login" value="login"></label>
      </div>
      </form>
<?php
  dumpPageFooter();
}

function action_webvalidate() {
  global $db;

  $Key = "";
  $formKey = $_SESSION['webloginformkey'];

  if ( array_key_exists("key", $_REQUEST) )
    $Key = $_REQUEST['key'];

  if ( array_key_exists("url", $_REQUEST) )
    $URL = $_REQUEST['url'];
  else
    die ('ERROR, you must pass in a URL value');

  $parsedURL = parse_url($URL);

  if (!isset($parsedURL["host"]))
    die ('ERROR, you must pass in a URL value');

  if ( array_key_exists("username", $_REQUEST) )
    $username =  utf8_clean_string($_REQUEST['username']);
  else
    die ('ERROR, you must pass in a USERNAME value');

  if ( array_key_exists("password", $_REQUEST) )
    $password =  $_REQUEST['password'];
  else
    die ('ERROR, you must pass in a PASSWORD value');

  /*$remember = FALSE;
  if ( array_key_exists("remember", $_REQUEST) )
    $remember =  $_REQUEST['remember'];*/

  $refererParts = parse_url($_SERVER['HTTP_REFERER']);
  $validReferer = (empty($_SERVER['HTTP_REFERER']) || empty($refererParts['host']) || $refererParts['host'] == $GLOBALS['config']['ourdomain']);

  if ($Key != $formKey || !$validReferer) {
    dumpPageHeader();
?>
      <div id="information">
        The website <b><?php echo htmlentities($parsedURL['host']); ?></b> is attempting to circumvent a part of the BZFlag weblogin system<br>
        Please contact the site owner to have them rectify the problem.<br>
        If the website in question had asked you for password, it is possible that the site may have stored your information. It is highly recommended you change your password immediately.
      </div>
<?php
    dumpPageFooter();
  }
  else {
    $player = $db->getActiveForumUserByName($username);
    if (!$player || !phpbb_check_hash($password, $player['user_password'])) {
      dumpPageHeader();
?>
      <div id="information">
        The username or password you entered was invalid.
      </div>
<?php
      dumpPageFooter();
    }
    else {
      $hostkey = md5($parsedURL["host"]);

      /*if ($remember) {
        $wlu = $hostkey.'wlu';
        $wlk = $hostkey.'wlk';
        setcookie($wlu, $playerid , time()+1209600);
        $key = md5($parsedURL["host"] . $row[1]);
        setcookie($wlk, $key , time()+1209600);
      }
      else {
        setcookie($hostkey.'webloginuser'.'webloginuser', "" , time()-3600);
        setcookie($hostkey.'webloginkey'.'webloginkey', "" , time()-3600);
      }*/

      $token = random_int(0, 2147483647);
      $nameport = $refererParts['host'];
      if (!empty($refererParts['port'])) {
        $nameport .= ':'.$refererParts['port'];
      }
      $db->setTokenInformationByUserID($player['user_id'], $token, $nameport);
      if (true) {
        header('location: ' . str_replace(Array('%TOKEN%', '%USERNAME%'), Array(urlencode($token), urlencode($player['username'])), $URL));
        return;
      }
    }
  }
}

// start of real script

session_start();

$db = new ListDB($dbhost, $dbuname, $dbpass, $dbname, $bbdbname);

// start of script
// figure out what we are doing
if ( array_key_exists('action', $_REQUEST) )
  $action =  $_REQUEST['action'];
else
  $action = 'weblogin';

switch ($action) {
case 'weblogin':
  action_weblogin();
  break;

case 'webvalidate':
  action_webvalidate();
break;

default:
  echo 'ERROR = 404, WTF? Command ' . $action ; ' not known';
  break;
}
