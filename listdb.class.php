<?php

class ListDB {
  var $link;

  function __construct($hostname, $username, $password, $database) {
    $this->link = new mysqli($hostname, $username, $password, $database);
    if ($this->link->connect_error) {
      die('Unable to connect to database');
    }

    $this->link->query("SET NAMES 'utf8'");
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
    return $this->getAllAssoc($this->link->query('SELECT type, value, owner, reason, silent FROM serverbans WHERE active = 1'));
  }

  function getAllBans() {
    return $this->getAllAssoc($this->link->query('SELECT * from serverbans'));
  }

  // Server advertisements

  function cleanupServerAdvertisements() {
    $delete = $this->link->prepare('DELETE FROM server_advert_groups WHERE server_id = ?');
    $result = $this->link->query('SELECT SAV.server_id as server_id from server_advert_groups as SAV LEFT JOIN servers  S ON S.server_id=SAV.server_id WHERE S.server_id is null');
    if ($result) {
      while ($row = $result->fetch_assoc()) {
        $delete->bind_param('i', $row['server_id']);
        $delete->execute();
      }
    }
  }


  // Servers

  function addServer($nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build) {
    $statement = $this->link->prepare('INSERT INTO servers (nameport, ipaddr, gameinfo, title, owner, ownername, version, build, lastmod) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    if ($statement) {
      $time = time();
      $statement->bind_param('ssssssssi', $nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build, $time);
      $statement->execute();
    }
  }

  function updateServerByServerID($serverid, $nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build) {
    $statement = $this->link->prepare('UPDATE servers SET nameport = ?, ipaddr = ?, gameinfo = ?, title = ?, owner = ?, ownername = ?, version = ?, build = ?, lastmod = ? WHERE server_id = ?');
    if ($statement) {
      $time = time();
      $statement->bind_param('ssssssssii', $nameport, $servip, $gameinfo, $title, $ownerID, $owner, $version, $build, $time, $serverid);
      $statement->execute();
    }
  }

  function deleteServerByServerID($serverid) {
    $statement = $this->link->prepare('DELETE FROM servers WHERE server_id = ?');
    if ($statement) {
      $statement->bind_param('i', $serverid);
      $statement->execute();
    }
  }

  function deleteStaleServers($staletime) {
    $statement = $this->link->prepare('DELETE FROM servers WHERE lastmod < ?');
    if ($statement) {
      $statement->bind_param('i', $staletime);
      $statement->execute();
    }
  }

  function getServerByNameport($nameport) {
    $statement = $this->link->prepare('SELECT * FROM servers WHERE nameport = ?');
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
    $statement = $this->link->prepare('INSERT INTO server_advert_groups (server_id, group_id) VALUES (?, ?)');
    if ($statement) {
      $statement->bind_param('ii', $serverid, $groupid);
      $statement->execute();
    }
  }

  function deleteAdvertGroupByServerID($serverid) {
    $statement = $this->link->prepare('DELETE FROM server_advert_groups WHERE server_id = ?');
    if ($statement) {
      $statement->bind_param('i', $serverid);
      $statement->execute();
    }
  }

  function getAuthKeyInfoByKey($authkey) {
    $statement = $this->link->prepare('SELECT host, owner FROM authkeys WHERE key_string = ?');
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
    $statement = $this->link->prepare('SELECT user_id, user_password, username FROM bzflag_forum.bzbb3_users WHERE username_clean = ? AND user_inactive_reason = 0');
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
    $statement = $this->link->prepare('SELECT username, username_clean, user_password FROM bzflag_forum.bzbb3_users WHERE user_id = ? AND user_inactive_reason = 0');
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
    $statement = $this->link->prepare('SELECT username_clean FROM bzflag_forum.bzbb3_users WHERE user_id = ? AND user_inactive_reason = 0');
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
    $statement = $this->link->prepare("SELECT g.group_name FROM bzflag_forum.bzbb3_groups g, bzflag_forum.bzbb3_user_group ug WHERE ug.user_id = ? AND ug.group_id = g.group_id AND ug.user_pending = 0 AND NOT (g.group_skip_auth = 1 AND ug.group_leader = 1)");
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

  function validateTokenInformation($callsign, $token, $ip, $staletime) {
    $statement = $this->link->prepare("SELECT user_id FROM bzflag_forum.bzbb3_users WHERE username_clean = ? AND user_token = ? AND user_tokendate > ? AND (user_tokenip = ? or '' = ?)");
    if ($statement) {
      $statement->bind_param('siiss', $callsign, $token, $staletime, $ip, $ip);
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

  function setTokenInformationByUserID($userid, $token) {
    $statement = $this->link->prepare('UPDATE bzflag_forum.bzbb3_users SET user_token = ?, user_tokendate = ?, user_tokenip = ? WHERE user_id = ?');
    if ($statement) {
      $time = time();
      $statement->bind_param('iisi', $token, $time, $_SERVER['REMOTE_ADDR'], $userid);
      $statement->execute();
    }
  }

  function clearTokenInformationByUserID($userid) {
    $statement = $this->link->prepare('UPDATE bzflag_forum.bzbb3_users SET user_lastvisit = ?, user_tokendate = 0 WHERE user_id = ?');
    if ($statement) {
      $time = time();
      $statement->bind_param('ii', $time, $userid);
      $statement->execute();
    }
  }

  function getPrivateMessageCountByUserID($userid) {
    $statement = $this->link->prepare('SELECT user_new_privmsg FROM bzflag_forum.bzbb3_users WHERE user_id = ?');
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
    $statement = $this->link->prepare("SELECT s.nameport, s.version, s.gameinfo, s.ipaddr, s.title, s.owner, s.ownername FROM servers s INNER JOIN server_advert_groups ad ON s.server_id = ad.server_id WHERE ad.group_id = 0 AND (s.version = ? OR '' = ?) ORDER BY nameport ASC");
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
    $statement = $this->link->prepare("SELECT s.nameport, s.version, s.gameinfo, s.ipaddr, s.title, s.owner, s.ownername FROM servers s INNER JOIN server_advert_groups ad ON s.server_id = ad.server_id INNER JOIN bzflag_forum.bzbb3_user_group ug ON ad.group_id = ug.group_id WHERE ug.user_id = ? AND (s.version = ? OR '' = ?) UNION SELECT s.nameport, s.version, s.gameinfo, s.ipaddr, s.title, s.owner, s.ownername FROM servers s INNER JOIN server_advert_groups ad ON s.server_id = ad.server_id WHERE (ad.group_id = 0 OR ad.group_id = 6727) AND (s.version = ? OR '' = ?) ORDER BY nameport ASC");
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
    $statement = $this->link->prepare('SELECT group_id FROM bzflag_forum.bzbb3_groups WHERE group_name = ?');
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
