<?php

// bzfls.php
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

/* If started from the command line, wrap parameters to $_POST and $_GET */
if (php_sapi_name() === 'cli') {
	parse_str($argv[1], $_REQUEST);
}

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

# where to send debug printing (might override below)
$debugLevel= 2;      // set to >2 to see all sql queries (>1 to see GET/POST input args)
$debugFilename  = '/var/log/bzfls/bzfls.log';
$debugNoIpCheck = 0;  // for testing ONLY !!!

// define dbhost/dbuname/dbpass/dbname here
// NOTE it's .php so folks can't read the source
include('/etc/bzflag/serversettings.php');

include('banfunctions.php');

debug('Connecting to the database', 3);

$db = new ListDB($dbhost, $dbuname, $dbpass, $dbname);

# for banning.  provide key => value pairs where the key is an
# ip address. value is not used at present. these are pulled
# from the serverbans table.
$banlist = $db->getActiveBans();

register_shutdown_function ('allDone');

$debugMessage = null;

function allDone (){

  global $debugMessage, $debugFilename;
  if ($debugMessage != null){
    $fdDebug = @fopen ($debugFilename, 'a');

   if ($fdDebug != null) {
      $request_info = (!isset($_SERVER['HTTP_X_FORWARDED_PROTO']) || $_SERVER['HTTP_X_FORWARDED_PROTO'] != 'https')?' HTTP':'';

      fwrite($fdDebug, date('D M j G:i:s T Y') . ' ' . str_pad($_SERVER['REMOTE_ADDR'],15) . $request_info
          . ' ' . str_replace ("\n", "\n  ", $debugMessage));
      if ($debugMessage[strlen($debugMessage)-1] != "\n")
        fputs ($fdDebug, "\n");
      fclose($fdDebug);
    }
  }

}

function debug ($message, $level=1) {
  global $debugMessage, $debugLevel;
  if ($level <= $debugLevel) {
    $debugMessage .= $message;
  }
}

function debugArray ($a){
  $arr = array();
  foreach ($a as $key => $val){
    if (strncasecmp ($key, "PASS", 4)==0)
      $val = "**PASSWORD FILTERED**";
    if (strpos($key, ' '))
      $key="\"$key\"";
    if (strpos($val, ' '))
      $val="\"$val\"";
    $arr[] = "$key=$val";
  }
  return str_replace (array ("\r", "\n"), array ('<\r>', '<\n>'), join(', ', $arr));
}


// temp debug (menotume 2006-05-22)
//if (strncasecmp ($_REQUEST['callsign'], "dutch", 5) == 0){
//  debug ("\n***** GLOBALS:\n");
//  debug (  print_r ($GLOBALS, true), 1 );
//}


if ($debugLevel > 1){
  if (count ($GLOBALS['_POST']))
    debug ("POST ARGS: " . debugArray ($GLOBALS['_POST']));
  if (count ($GLOBALS['_GET']))
    debug ("GET ARGS: " . debugArray ($GLOBALS['_GET']));
}

function validate_string($string, $valid_chars, $return_invalid_chars) {
  # thanx http://scripts.franciscocharrua.com/validate-string.php =)
  $invalid_chars = '';

  if ($string == null || $string == '')
    return(true);

  # for every char
  for ($index = 0; $index < strlen($string); $index++) {
    $char = substr($string, $index, 1);
    # valid char?
    if (strpos($valid_chars, $char) === false) {
      # if not, is it on the list of invalid characters?
      if (strpos($invalid_chars, $char) === false) {
        # if not, add it.
        $invalid_chars .= $char;
      }
    }
  }

  # if the string does not contain invalid characters, the function will return true.
  # if it does, it will either return false or a list of the invalid characters used
  # in the string, depending on the value of the second parameter.
  if($return_invalid_chars == true && $invalid_chars != '')
    return($invalid_chars);
  else
    return($invalid_chars == '');
}

# validate string or error
function validate_string_or_error($string, $valid_chars) {
  $invalid_chars = validate_string($string, $valid_chars, true);
  if ($invalid_chars == true) {
    return($string);
  }
  header('Content-Type: text/html');
  print("ERROR: Invalid chars in \"$string\": \"$invalid_chars\"");
  return('');
}

# validate string or die
function validate_string_or_die($string, $valid_chars) {
  if ($string == '') {
    return $string;
  }
  $string = validate_string_or_error($string, $valid_chars);
  if ($string === '') {
    die('');
  }
  return($string);
}

# validate callsign or error (restrictive, used for more than callsign)
function vcsoe($string) {
  # against better judgement " " is valid here =(
  $valid_chars = ' -_.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return(validate_string_or_error($string, $valid_chars));
}

# validate hex or die
function vhod($string) {
  $valid_chars = '1234567890abcdef';
  return(validate_string_or_die($string, $valid_chars));
}

# validate nameport or die
function vnpod($string) {
  $valid_chars = '-.:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return(validate_string_or_die($string, $valid_chars));
}

# validate checktoken or die
function vctod($string) {
  $valid_chars = '\r\n=-_.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return(validate_string_or_die($string, $valid_chars));
}

# validate email or die
function veod($string) {
  $valid_chars = '-.@1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return(validate_string_or_die($string, $valid_chars));
}

# Common to all
if (array_key_exists('action', $_REQUEST)) {
  $action = vcsoe($_REQUEST['action']);
} else {
  $action = '';
}
# For ADD REMOVE
$nameport = vnpod(@$_REQUEST['nameport']);
$serverKey = @$_REQUEST['key'];
# For ADD
$build    = vcsoe(@$_REQUEST['build']);
$version  = vcsoe(@$_REQUEST['version']); # also on LIST
$gameinfo = vhod(@$_REQUEST['gameinfo']);
$title = @$_REQUEST['title']; # escape for SQL calls
# for ADD CHECKTOKENS
$checktokens = vctod(@$_REQUEST['checktokens']); # callsign0=token\ncallsign1=token\n...
$groups   = vctod(@$_REQUEST['groups']); # groups server is interested in

# For players
$callsign = vcsoe(@$_REQUEST['callsign']);  # urlencoded
$email    = veod(@$_REQUEST['email']);     # urlencoded
#$password = vcsoe(@$_REQUEST['password']);  # urlencoded
$password = @$_REQUEST['password'];

# for LIST
$listformat = vcsoe(@$_REQUEST['listformat']);


function testform($message) {
  header('Content-Type: text/html');
  print('<html>
<head>
<title>BZFlag db server</title>
</head>
<body>
  <h1>BZFlag db server</h1>
  ' . $message . '
  <p>This is the development interface to the <a href="http://BZFlag.org/">BZFlag</a> list server AT BZ.</p>
  <form action="" method="POST">
    action:<select name="action">
    <option value="LIST" selected>LIST - list servers</option>
    <option value="ADD">ADD - add a server</option>
    <option value="REMOVE">REMOVE - remove a server</option>
    <option value="CHECKTOKENS">CHECKTOKENS - verify player token from game server</option>
    <option value="GETTOKEN">GETTOKEN - get player token</option>
    <option value="UNKNOWN">UNKNOWN - test invalid request</option>
    </select><br>
    list_format:<select name="listformat">
    <option value="plain" selected>plain</option>
    <option value="lua">lua</option>
    <option value="json">json</option>
    </select><br>
    actions: LIST<br>
    version:<input type="text" name="version" size="80"><br>
    callsign:<input type="text" name="callsign" size="80"><br>
    password:<input type="password" name="password" size="80"><br>
    actions: REMOVE<br>
    nameport:<input type="text" name="nameport" size="80"><br>
    actions: ADD REMOVE<br>
    build:<input type="text" name="build" size="80"><br>
    gameinfo:<input type="text" name="gameinfo" size="80"><br>
    title:<input type="text" name="title" size="80"><br>
    advertgroups:<input type="text" name="advertgroups" size="40" maxsize=1000><br>
    actions: ADD CHECKTOKENS<br>
    checktokens:<textarea name="checktokens" rows="3" style="width:100%">
CallSign0@127.0.0.1=01234567
CallSign1=89abcdef</textarea>
    groups:<textarea name="groups" rows="3" style="width:100%">
Group0
Group1</textarea>
    actions: REGISTER CONFIRM<br>
    email:<input type="text" name="email" size="80"><br>
    <input type="submit" value="Post entry">
    <input type="reset" value="Clear form">
  </form>
</body>
</html>');
}



function lua_quote($str)
{
  return '"' . addslashes($str) . '"';
}


function json_quote($str)
{
  return '"' . addslashes($str) . '"';
}


function print_plain_list(&$listing)
{
  header('Content-Type: text/plain; charset=utf-8');
  if (isset($listing['token'])) {
    if ($listing['token']) {
      print("TOKEN: " . $listing['token'] . "\n");
    } else {
      print("NOTOK: invalid callsign or password\n");
    }
  }
  if (isset($listing['notice'])) {
    print("NOTICE: " . $listing['notice'] . "\n");
  }
  if ($_SERVER['SERVER_PORT'] != '443' && (!isset($_SERVER['HTTP_X_FORWARDED_PROTO']) || $_SERVER['HTTP_X_FORWARDED_PROTO'] != 'https'))
    echo "outdated.bzflag.org BZFS0221 00000010000100000000000000000000c8c8c800c800c800c800c800c8 127.0.0.1 You are using a very old client. Upgrade to BZFlag 2.4.4 or later.\n";
  foreach ($listing['servers'] as $server) {
    print("{$server['nameport']} {$server['version']} {$server['gameinfo']} {$server['ipaddr']} {$server['title']}\n");
  }
}


function print_lua_list(&$listing)
{
  header('Content-Type: text/x-lua; charset=utf-8');
  print "return {\n";
  if (isset($listing['token'])) {
    print "token = " . lua_quote($listing['token']) . ",\n";
  }
  print "fields = { 'version', 'hexcode', 'addr', 'ipaddr', 'title', 'owner' },\n";
  //print "fields = { 'version', 'hexcode', 'addr', 'ipaddr', 'title', 'owner', 'ownername' },\n";
  print "servers = {\n";
  foreach ($listing['servers'] as $server) {
    print "{"
    . lua_quote($server['version']) . ","     // version
    . lua_quote($server['gameinfo']) . ","     // hexcode
    . lua_quote($server['nameport']) . ","     // addr
    . lua_quote($server['ipaddr']) . ","     // ipaddr
    . lua_quote($server['title']) . ","     // title
    //. lua_quote($server['owner']) . ","    // owner
    . lua_quote($server['ownername']) . "},\n"; // ownername
  }
  print "}\n"; // end the "servers" table
  print "}\n";
}


function print_json_list(&$listing)
{
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($listing,JSON_PRETTY_PRINT);
}

function authenticate_player($callsign, $password) {
  global $db;
  // Clean up UTF-8 characters
  $clean_callsign = utf8_clean_string($callsign);

  // See if this player is registered
  $player = $db->getActiveForumUserByName($clean_callsign);

  // If not registered or the password is wrong, use an empty token
  if ($player && phpbb_check_hash($password, $player['user_password'])) {
    unset($player['user_password']);
    // Generate a random token
    $player['token'] = random_int(0, 2147483647);
    //$player['token'] = bin2hex(random_bytes(16));
    //$player['token'] = base64_encode(random_bytes(14));
    debug ("OK   token={$player['token']}", 2);
    $db->setTokenInformationByUserID($player['user_id'], $player['token']);
    return $player;
  }
  else {
    debug ("NOTOK", 2);
    return false;
  }
}


function action_list() {
  #  -- LIST --
  # Same as LIST in the old bzfls
  global $db, $callsign, $password, $version;
  global $listformat;
  debug ("  :::::  ", 2);

  $listing = Array();

  # remove all inactive servers from the table
  debug('Deleting inactive servers from list', 3);
  $db->deleteStaleServers(time() - 1830);

  if ($db->getAffectedRows() > 0)
    $db->cleanupServerAdvertisements();

  if ($callsign && $password) {
    $player = authenticate_player($callsign, $password);

    // If not registered or the password is wrong, use an empty token
    if (!$player) {
      $listing['token'] = ""; // empty token is a bad token
      $listing['servers'] = $db->getServersForUnregistered($version);
    } else {
      // Generate a random token
      $listing['token'] = $player['token'];

      // Get servers
      $listing['servers'] = $db->getServersForUserID($player['user_id'], $version);

      // Check for private messages and send a notice if there is one
      $pms = $db->getPrivateMessageCountByUserID($player['user_id']);
      if ($pms) {
        $listing['notice'] = "You have $pms private messages waiting for you, $callsign.  Log in at https://forums.bzflag.org/ to read them.";
      }
    }
  }
  else {
    $listing['servers'] = $db->getServersForUnregistered($version);
  }

  if ($listformat == "lua" || $listformat == "json") {
    $listing['fields'] = Array("addr", "version", "hexcode", "ipaddr", "title", "owner", "ownername");
  }

  switch ($listformat) {
    case "lua":  { print_lua_list($listing);   break; }
    case "json": { print_json_list($listing);  break; }
    default:     { print_plain_list($listing); break; }
  }
}


function action_gettoken () {
  global $db, $callsign, $password, $version;
  header('Content-type: text/plain');
  debug('Fetching TOKEN', 2);

  if ($callsign && $password) {
    $player = authenticate_player($callsign, $password);
    if ($player) {
      print("TOKEN: {$player['token']}\n");
    }
    else {
      print("NOTOK: invalid callsign or password\n");
    }
  }
}

function checktoken($callsign, $ip, $token, $garray) {
  # validate player token for connecting player on a game server
  global $db;
  # TODO add grouplist support
  print("MSG: checktoken callsign=$callsign, ip=$ip, token=$token ");
  foreach($garray as $group) {
    print(" group=$group");
  }
  print("\n");
  $timeout = 300; # 60 minutes while testing
  $staletime = time() - 300;

  $clean_callsign = utf8_clean_string($callsign);

  if (!$db->userExists($clean_callsign)) {
    print ("UNK: $callsign\n");
    debug ("UNK:$callsign ", 2);
    return;
  }

  $playerid = $db->validateTokenInformation($clean_callsign, $token, $ip, $staletime);
  if ($playerid) {
    # clear tokendate so nasty game server admins can't login someplace else
    $db->clearTokenInformationByUserID($playerid);
    print ("TOKGOOD: $callsign");
    if (count($garray)) {
      $playergroups = $db->getGroupMembershipsByUserID($playerid);
      $commongroups = array_intersect($garray, $playergroups);
      print(':' . implode(':', $commongroups));
    }
    print ("\n");

    # Send the BZID
    # - the BZID can be any uniquely identifying invariant string
    # - bzfs is setup to accept spaces if the strings is "quoted"
    print ("BZID: $playerid $callsign\n");
    debug ("TOKGOOD: $callsign ", 2);
  } else {
    print ("TOKBAD: $callsign\n");
    debug ("TOKBAD:$callsign ", 2);
  }
}

function action_checktokens() {
  #  -- CHECKTOKENS --
  # validate callsigns and tokens (clears tokens)
  global $checktokens, $groups;
  debug ("  :::::  ", 2);
  if ($checktokens != '') {
    function remove_empty ($value) { return empty($value) ? false : true; }
    $garray = array_filter(explode("\r\n", $groups), 'remove_empty');
    foreach(array_filter(explode("\r\n", $checktokens), 'remove_empty') as $checktoken) {
      list($callsign, $rest) = explode('@', $checktoken);
      if ($rest) {
        list($ip, $token) = explode('=', $rest);
      } else {
        $ip = '';
        list($callsign, $token) = explode('=', $checktoken);
      }
      if ($token) checktoken($callsign, $ip, $token, $garray);
    }
  }
}

function add_advertList ($serverID){
  global $db;

  $adverts = $_REQUEST['advertgroups'];
  $advertList = explode (',', $adverts);

  if (!isset($adverts) || in_array('EVERYONE', $advertList)) {
    $db->addAdvertGroup($serverID, 0);
  }
  else {
    foreach($advertList as $groupname) {
      $groupid = $db->getGroupIDByGroupName($groupname);
      if ($groupid)
        $db->addAdvertGroup($serverID, $groupid);
    }
  }
}

function action_add() {
  #  -- ADD --
  # Server either requests to be added to DB, or to issue a keep-alive so that it
  # does not get dropped due to a timeout...
  global $db, $nameport, $version, $build, $gameinfo, $title, $checktokens, $groups, $debugNoIpCheck, $serverKey;
  header('Content-type: text/plain');
  debug("Attempting to ADD $nameport $version $gameinfo $title", 3);

  $owner = "";
  $ownerID = "";

  // check the server key (from the bzfs -publickey option)
  if ( ($version != 'BZFS0026' && $version != 'BZFS1910') || $serverKey)
  {
    $keyinfo = $db->getAuthKeyInfoByKey($serverKey);
    if (!$keyinfo) {
      print("ERROR: Missing or invalid server authentication key\n");
      return;
    }

    # FIXME: this only looks one IPv4 address
    # server may have zero or more IPv4 ips, and zero or more IPv6 ips.
    $ip = gethostbyname($keyinfo['host']);
    if ($ip != $_SERVER['REMOTE_ADDR']) {
      echo "WARNING: Host mismatch for server authentication key $ip != " . $_SERVER['REMOTE_ADDR'] . "\n";
      #return;
    }

    // ok so the key is good, now to check the owner
    $owner = $db->getActiveForumUsernameCleanByUserID($keyinfo['owner']);
    if (!$owner) {
      print("ERROR: Owner lookup failure\n");
      return;
    }
    $ownerID = $keyinfo['owner'];
  }

  # Filter out badly formatted or buggy versions
  print "MSG: ADD $nameport $version $gameinfo $title\n";
  if (!preg_match('/[A-Z]{4}[0-9]{4}/', $version))
    return;

  $split = explode(':', $nameport);
  $servname = $split[0];
  if (array_key_exists(1, $split))
    $servport = $split[1];
  else
    $servport = 5154;

  $serverips = gethostbynamel($servname);
  // Hostname must resolve to a single IPv4 address
  if ($serverips === FALSE || sizeof($serverips) != 1) {
    print("ERROR: Provided hostname does not resolve to a single IPv4 address\n");
    return;
  }

  $servip = $serverips[0];

  if ($_SERVER['REMOTE_ADDR'] !== $servip && !$debugNoIpCheck) {
    debug('Requesting address is ' . $_SERVER['REMOTE_ADDR']
        . ' while server is at ' . $servip, 1 );
    print('ERROR: Requesting address is ' . $_SERVER['REMOTE_ADDR']
        . ' while server is at ' . $servip );
    die();
  }

  # Test to see whether nameport is valid by attempting to establish a
  # connection to it
  $fp = @fsockopen($servname, $servport, $errno, $errstring, 5);
  if (!$fp) {
    //debug('Unable to connect back to '.$servname.':'.$servport, 1);
    print("ERROR: Unable to reach your server. Check your router/firewall and DNS configuration.\n");
    return;
  }
  # FIXME - should callback and update all stats instead of bzupdate.pl
  fclose ($fp);

  $server = $db->getServerByNameport($nameport);

  if ($server) {
    debug("Server already exists in database -- updating", 3);
    print("MSG: updating $nameport\n");
    $db->updateServerByServerID($server['server_id'], $nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build);
  }
  else {
    debug('Server does not already exist in database -- adding', 3);
    print("MSG: adding $nameport\n");
    $db->addServer($nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build);
    $server = $db->getServerByNameport($nameport);
    if ($server)
      add_advertList($server['server_id']);
  }

  if ($owner)
    print "OWNER: $owner\n";

  action_checktokens();
  debug("ADD $nameport", 3);
  print "ADD $nameport\n";
}

function action_remove() {
  #  -- REMOVE --
  # Server requests to be removed from the DB.
  global $db, $nameport, $debugNoIpCheck;
  header('Content-type: text/plain');
  print("MSG: REMOVE request from $nameport\n");
  debug("REMOVE request from $nameport", 1);

  $split = explode(':', $nameport);
  $servname = $split[0];
  if (array_key_exists(1, $split))
    $servport = $split[1];
  else
    $servport = 5154;

  $serverips = gethostbynamel($servname);
  // Hostname must resolve to a single IPv4 address
  if ($serverips === FALSE || sizeof($serverips) != 1) {
    print("ERROR: Provided hostname does not resolve to a single IPv4 address\n");
    return;
  }

  $servip = $serverips[0];

  if ($_SERVER['REMOTE_ADDR'] !== $servip && !$debugNoIpCheck) {
    debug('Requesting address is ' . $_SERVER['REMOTE_ADDR']
        . ' while server is at ' . $servip, 1 );
    print('ERROR: Requesting address is ' . $_SERVER['REMOTE_ADDR']
        . ' while server is at ' . $servip );
    die();
  }

  $server = $db->getServerByNameport($nameport);
  if ($server) {
    $db->deleteServerByServerID($server['server_id']);
    $db->deleteAdvertGroupByServerID($server['server_id']);
  }
  print("REMOVE: $nameport\n");
}

# set up a list of addresses to check
$values = Array();
$values['ipaddress'][0] = $_SERVER['REMOTE_ADDR'];
$values['hostname'][0] = gethostbyaddr($_SERVER['REMOTE_ADDR']);

# If the hostname value came back as an IP, there wasn't a reverse DNS name,
# so ditch it
if ($values['hostname'][0] == $values['ipaddress'][0])
  unset($values['hostname'][0]);

# TODO: Add a check for the $nameport variable here and add that to $values

# ignore banned servers outright
if ($ban = IsBanned($values, $banlist, $isSilent)) {
  # reject the connection attempt
  header('Content-type: text/plain');
  $remote_addr = $_SERVER['REMOTE_ADDR'];
  debug("Connection rejected from $remote_addr", 1);
  if ($ban['silent'])
    exit;
  else
    die("ERROR: Connection attempt rejected.  See #bzflag on irc.freenode.net\n");
}

# tell the proxies not to cache
header('Cache-Control: no-cache');
header('Pragma: no-cache');
header("Connection: close");

# Do stuff based on what the 'action' is...
switch ($action) {
  case 'LIST':     { action_list();       break; }
  case 'GETTOKEN': { action_gettoken();   break; }
  case 'ADD':      { action_add();        break; }
  case 'REMOVE':   { action_remove();     break; }
  case 'REGISTER': { action_register();   break; }
  case 'CONFIRM':  { action_confirm();    break; }
  case 'CHECKTOKENS': {
    header('Content-type: text/plain');
    action_checktokens();
    break;
  }
  default: {
    # TODO dump the default form here but still close the database connection
    testform('Unknown command: \'' . $action . '\'');
  }
}

debug('End session', 4);

# Local Variables: ***
# mode:php ***
# tab-width: 8 ***
# c-basic-offset: 2 ***
# indent-tabs-mode: t ***
# End: ***
# ex: shiftwidth=2 tabstop=8
