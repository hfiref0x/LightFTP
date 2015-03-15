# LightFTP
* Small x86-32/x64 Windows FTP Server

# System Requirements

* x86-32/x64 Windows Vista/7/8/8.1/10.
* No admin rights required. FTP server must be allowed in firewall.

# Configuration

Stored in fftp.cfg file, contain configuration section named ftpconfig and number of sections 

describing users and their privileges. 

ftpconfig section values:
* port = unsigned integer, connection port number, allowed range 0..65535
* maxusers = unsigned integer, maximum number of users allowed to connect
* interface = quoted string, network interface to bind ftp server to, for all interfaces use "0.0.0.0"
* logfilepath = quoted string, path to ftp log file, e.g. "C:\TEMP"

User section values:
* pswd = string, user password, specify * as any password
* accs = string, access right, see "Available user access rights"
* root = quoted string, path to user home directory.

Available user access rights:
* admin - read, write, append, delete, rename
* banned - user not allowed to connect
* readonly - browse and download
* upload - creating new directories, store new files, append disabled
* Note: any other access right is similar to banned.

Example of configuration file can be found in Compiled directory.

# Build 

* LightFTP comes with full source code.
* In order to build from source you need Microsoft Visual Studio 2013 U4 and later versions.
 

# Authors

(c) 2007 - 2015 LightFTP Project
