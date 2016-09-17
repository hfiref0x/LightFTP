# LightFTP
* Small x86-32/x64 FTP Server

# System Requirements

* x86-32/x64 Windows Vista/7/8/8.1/10.
* x86-32/x64 POSIX compliant OS, e.g. Linux.
* No admin/root privileges required. FTP server must be allowed in firewall.

# Configuration

Stored in fftp.cfg file, contain configuration section named ftpconfig and number of sections describing users and their privileges. 

ftpconfig section values:
* port = unsigned integer, connection port number, allowed range 0..65535
* maxusers = unsigned integer, maximum number of users allowed to connect
* interface = string, network interface to bind ftp server to, for all interfaces use "0.0.0.0"
* logfilepath = string, path to ftp log file, e.g. "C:\TEMP" (/home/ExampleUserName/ExampleDataDirectory/fftplog for Linux), logged data append to the end of file

User section values:
* pswd = string, user password, specify * as any password
* accs = string, access right, see "Available user access rights"
* root = string, path to user home directory.

Available user access rights:
* admin - read, write, append, delete, rename
* readonly - browse and download
* upload - creating new directories, store new files, append disabled
* Note: any other access right is similar to banned (user not allowed to connect).

Example of configuration file can be found in Compiled directory.

# Build 

* LightFTP comes with full source code, written in C.
* In order to build from source in Windows you need Microsoft Visual Studio 2013/2015 and later versions. Source files (including VS project) located in Source/Windows directory.
* In order to build from source in Linux you need GCC C compiler, run make command in the Release directory. Sources files (including makefile) located in Source/Other directory.

# Authors

(c) 2007 - 2016 LightFTP Project
