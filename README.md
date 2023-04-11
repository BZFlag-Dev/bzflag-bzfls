# BZFlag List Server (bzfls)

------------------------------------------------------------------------------

The BZFlag List Server handles authentication and listing game servers.

* **bzfls.php:** The main entry point that is used to list game servers and handle authentication.
* **bzflsadmin.php:** Manages the list of bans used by bzfls.php, which can block servers or players.
* **weblogin.php:** Used by third-party websites to integrate with BZFlag's login system.

## Web Server Configuration

For Apache, include an alias:
```apacheconf
Alias /db/ /bzfls.php
```