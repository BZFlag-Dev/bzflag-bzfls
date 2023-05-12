<?php

class ListDB {
  // Database link
  var $link;

  // Forum database name and prefix
  private $forum_prefix = '';

  function __construct($hostname, $username, $password, $database, $forumdb, $forumprefix) {
    $this->link = new mysqli($hostname, $username, $password, $database);
    if ($this->link->connect_error) {
      die('Unable to connect to database');
    }

    if (!empty($forumdb))
      $this->forum_prefix = $forumdb . '.' . $forumprefix;

    $this->link->query("SET NAMES 'utf8'");
  }

  // Wrapper for mysqli::prepare that adds the forum prefix
  private function prepare($sql) {
    return $this->link->prepare(str_replace('%forum%', $this->forum_prefix, $sql));
  }

  // Wrapper for mysqli::query that adds the forum prefix
  private function query($sql) {
    return $this->link->query(str_replace('%forum%', $this->forum_prefix, $sql));
  }

  function getAffectedRows() { return $this->link->affected_rows; }

  private function getAllAssoc($result) {
    $rows = Array();
    while ($row = $result->fetch_assoc()) {
      $rows[] = $row;
    }
    return $rows;
  }

  /************************************
   * List tables
   *
   */

  // Bans

  function getActiveBans() {
    return $this->getAllAssoc($this->query('SELECT type, value, owner, reason, silent FROM serverbans WHERE active = 1'));
  }

  function getAllBans() {
    return $this->getAllAssoc($this->query('SELECT * from serverbans'));
  }

  // Server advertisements

  function cleanupServerAdvertisements() {
    $delete = $this->prepare('DELETE FROM server_advert_groups WHERE server_id = ?');
    $result = $this->query('SELECT SAV.server_id as server_id from server_advert_groups as SAV LEFT JOIN servers  S ON S.server_id=SAV.server_id WHERE S.server_id is null');
    if ($result) {
      while ($row = $result->fetch_assoc()) {
        $delete->bind_param('i', $row['server_id']);
        $delete->execute();
      }
    }
  }


  // Servers

  function addServer($nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build) {
    $statement = $this->prepare('INSERT INTO servers (nameport, ipaddr, gameinfo, title, owner, ownername, version, build, lastmod) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    if ($statement) {
      $time = time();
      $statement->bind_param('ssssssssi', $nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build, $time);
      $statement->execute();
    }
  }

  function updateServerByServerID($serverid, $nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build) {
    $statement = $this->prepare('UPDATE servers SET nameport = ?, ipaddr = ?, gameinfo = ?, title = ?, owner = ?, ownername = ?, version = ?, build = ?, lastmod = ? WHERE server_id = ?');
    if ($statement) {
      $time = time();
      $statement->bind_param('ssssssssii', $nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build, $time, $serverid);
      $statement->execute();
    }
  }

  function deleteServerByServerID($serverid) {
    $statement = $this->prepare('DELETE FROM servers WHERE server_id = ?');
    if ($statement) {
      $statement->bind_param('i', $serverid);
      $statement->execute();
    }
  }

  function deleteStaleServers($staletime) {
    $statement = $this->prepare('DELETE FROM servers WHERE lastmod < ?');
    if ($statement) {
      $statement->bind_param('i', $staletime);
      $statement->execute();
    }
  }

  function getServerByNameport($nameport) {
    $statement = $this->prepare('SELECT * FROM servers WHERE nameport = ?');
    if ($statement) {
      $statement->bind_param('s', $nameport);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();

        if ($row) return $row;
      }
    }

    return false;
  }



  function addAdvertGroup($serverid, $groupid) {
    $statement = $this->prepare('INSERT INTO server_advert_groups (server_id, group_id) VALUES (?, ?)');
    if ($statement) {
      $statement->bind_param('ii', $serverid, $groupid);
      $statement->execute();
    }
  }

  function deleteAdvertGroupByServerID($serverid) {
    $statement = $this->prepare('DELETE FROM server_advert_groups WHERE server_id = ?');
    if ($statement) {
      $statement->bind_param('i', $serverid);
      $statement->execute();
    }
  }

  function getAuthKeyInfoByKey($authkey) {
    $statement = $this->prepare('SELECT host, owner FROM authkeys WHERE key_string = ?');
    if ($statement) {
      $statement->bind_param('s', $authkey);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();

        if ($row) return $row;
      }
    }

    return false;
  }




  /************************************
   * Forum tables
   *
   */

  function userExists($name) {
    return !!$this->getActiveForumUserByName($name);
  }

  function getActiveForumUserByName($name) {
    $statement = $this->prepare('SELECT user_id, user_password, username FROM %forum%users WHERE username_clean = ? AND user_inactive_reason = 0');
    if ($statement) {
      $statement->bind_param('s', $name);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();

        if ($row) return $row;
      }
    }

    return false;
  }

  function getActiveForumUserByUserID($userid) {
    $statement = $this->prepare('SELECT username, username_clean, user_password FROM %forum%users WHERE user_id = ? AND user_inactive_reason = 0');
    if ($statement) {
      $statement->bind_param('i', $userid);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();

        if ($row) return $row;
      }
    }

    return false;
  }

  function getActiveForumUsernameCleanByUserID($userid) {
    $statement = $this->prepare('SELECT username_clean FROM %forum%users WHERE user_id = ? AND user_inactive_reason = 0');
    if ($statement) {
      $statement->bind_param('i', $userid);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();

        if ($row) return $row['username_clean'];
      }
    }

    return false;
  }

  function getGroupMembershipsByUserID($userid) {
    $statement = $this->prepare("SELECT g.group_name FROM %forum%groups g, %forum%user_group ug WHERE ug.user_id = ? AND ug.group_id = g.group_id AND ug.user_pending = 0 AND NOT (g.group_skip_auth = 1 AND ug.group_leader = 1)");
    if ($statement) {
      $statement->bind_param('i', $userid);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $groups = Array();
        while ($row = $result->fetch_assoc()) {
          $groups[] = $row['group_name'];
        }
        $statement->free_result();
        return $groups;
      }
    }

    return Array();
  }

  function validateTokenInformation($callsign, $token, $ip, $staletime, $nameport) {
    $statement = $this->prepare("SELECT user_id FROM %forum%users WHERE username_clean = ? AND user_token = ? AND user_tokendate > ? AND ((user_tokenip = ? OR '' = ?) OR (user_tokennameport = ? OR '' = ?))");
    if ($statement) {
      $statement->bind_param('siissss', $callsign, $token, $staletime, $ip, $ip, $nameport, $nameport);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();
        return $row['user_id'];
      }
    }

    return false;
  }

  function setTokenInformationByUserID($userid, $token, $nameport) {
    $statement = $this->prepare('UPDATE %forum%users SET user_token = ?, user_tokendate = ?, user_tokenip = ?, user_tokennameport = ? WHERE user_id = ?');
    if ($statement) {
      $time = time();
      $statement->bind_param('iissi', $token, $time, $_SERVER['REMOTE_ADDR'], $nameport, $userid);
      $statement->execute();
    }
  }

  function clearTokenInformationByUserID($userid) {
    $statement = $this->prepare('UPDATE %forum%users SET user_lastvisit = ?, user_tokendate = 0 WHERE user_id = ?');
    if ($statement) {
      $time = time();
      $statement->bind_param('ii', $time, $userid);
      $statement->execute();
    }
  }

  function getPrivateMessageCountByUserID($userid) {
    $statement = $this->prepare('SELECT user_new_privmsg FROM %forum%users WHERE user_id = ?');
    if ($statement) {
      $statement->bind_param('i', $userid);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();
        if ($row) return $row['user_new_privmsg'];
      }
    }

    return 0;
  }

  function getServersForUnregistered($version) {
    if (!$version) $version = '';
    $statement = $this->prepare("SELECT s.nameport, s.version, s.gameinfo, s.ipaddr, s.title, s.owner, s.ownername FROM servers s INNER JOIN server_advert_groups ad ON s.server_id = ad.server_id WHERE ad.group_id = 0 AND (s.version = ? OR '' = ?) ORDER BY nameport ASC");
    if ($statement) {
      $statement->bind_param('ss', $version, $version);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $rows = $this->getAllAssoc($result);
        $statement->free_result();
        return $rows;
      }
    }

    return Array();
  }

  function getServersForUserID($user, $version) {
    if (!$version) $version = '';
    $statement = $this->prepare("SELECT s.nameport, s.version, s.gameinfo, s.ipaddr, s.title, s.owner, s.ownername FROM servers s INNER JOIN server_advert_groups ad ON s.server_id = ad.server_id INNER JOIN %forum%user_group ug ON ad.group_id = ug.group_id WHERE ug.user_id = ? AND (s.version = ? OR '' = ?) UNION SELECT s.nameport, s.version, s.gameinfo, s.ipaddr, s.title, s.owner, s.ownername FROM servers s INNER JOIN server_advert_groups ad ON s.server_id = ad.server_id WHERE (ad.group_id = 0 OR ad.group_id = 6727) AND (s.version = ? OR '' = ?) ORDER BY nameport ASC");
    if ($statement) {
      $statement->bind_param('issss', $user, $version, $version, $version, $version);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $rows = $this->getAllAssoc($result);
        $statement->free_result();
        return $rows;
      }
    }

    return Array();
  }


  function getGroupIDByGroupName($groupname) {
    $statement = $this->prepare('SELECT group_id FROM %forum%groups WHERE group_name = ?');
    if ($statement) {
      $statement->bind_param('s', $groupname);
      $statement->execute();
      $result = $statement->get_result();
      if ($result) {
        $row = $result->fetch_assoc();
        $statement->free_result();
        if ($row) return $row['group_id'];
      }
    }

    return false;
  }
}
