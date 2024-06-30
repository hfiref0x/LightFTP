[![Build status](https://ci.appveyor.com/api/projects/status/0mvll9a7emrqo0a7?svg=true)](https://ci.appveyor.com/project/hfiref0x/lightftp)

# LightFTP
* Small x86-32/x64 FTP Server

# System Requirements

* x86-32/x64 POSIX compliant OS, e.g. Linux.
* x86-32/x64 Windows 7/8/8.1/10 with Cygwin (see Build section of this readme).
* No admin/root privileges required. FTP server must be allowed in firewall.

# Configuration

Stored in fftp.conf file, contain configuration section named ftpconfig and number of sections describing users and their privileges. 

#### [ftpconfig]

      port

Port number to bind the server to.
Default: 21

      maxusers

Maximum connections count to the server, that can be established simultaneously.
Default: 1

      interface

Interface IP to bind to. Use 0.0.0.0 to listen on any available interface.
Default: 127.0.0.1

      external_ip

If you running the server behind a NAT, it is a good idea to put your real IP here.
This will help clients to establish data connections.
Default: 0.0.0.0

      local_mask

IP mask for local network.
This will help the server to distinguish between local and Internet clients.
Default: 255.255.255.0

      minport
      maxport

Port range for data connections. You can use it to configurate port forwarding on your gateway device.
Default: 1024..65535

      logfilepath

Full path with file name for a log file. Comment or delete it to disable logging.
Default: disabled

      CATrustFile

It is recommended to leave this option as it is (/etc/ssl/certs/ca-certificates.crt)

      ServerCertificate

Path to your SSL certificate. Accepted format is x509 ASCII PEM.

      Keyfile

Path to PEM private key file for your certificate.

      KeyfilePassword

Password to decrypt private key.

      keepalive

Send keepalive packets (some NATs may require this).
Default: 0 (disabled)


# User sections

Note for "accs" field:

      banned

not allowed to log in

      readonly

just read directories and download files

      upload

creating new directories, store new files. Append, rename and delete disabled.
      
      admin

all the features enabled.

Note for "pswd" field:
pswd=* means "any password is match"

Example of configuration file can be found in Source directory as fftp.conf.

# Build 

* LightFTP comes with full source code, written in C;
* In order to build from source in Windows you need Cygwin environment (https://www.cygwin.com/) with GNU make, gnutls and pthreads packages installed. Also make sure Cygwin bin folder is set in system wide PATH variable (e.g. PATH=SomeOfYourOtherValues;C:\Cygwin\bin;C:\Cygwin\usr\bin). To build executable run make command in the Release directory;
* In order to build from source in Linux you need GCC C compiler, run make command in the Release directory. LigthFTP uses GnuTLS, make sure you have headers (libgnutls-dev or gnutls-dev) installed.

### Example for Linux Mint 19.3/Ubuntu 18.04

You need GCC and Make installed. If they are not installed you can install them as part of build-essential package:

      sudo apt install build-essential
      
LightFTP uses GnuTLS library. It need to be installed before compiling LightFTP. To install it, open terminal and use:

      sudo apt install gnutls-dev
	  
or if this doesn't work try:

      sudo apt install libgnutls28-dev  
      
You can download source from https://github.com/hfiref0x/LightFTP/releases or use git. 

In case if you want to use git and git is not installed, install it first:

      sudo apt install git
      
Next use the following:

      git clone https://github.com/hfilef0x/lightftp
      cd lightftp/Source/Release
      make
      
Result binary is fftp. Next setup ftp config, example config file is Bin/fftp.conf. Set port, accounts, path to log file (optionally if you need it), path to certificates if you want to use them, etc.

# Old Windows version

Since 2.2 old Windows unmaintained version moved to the separate archive repository, https://github.com/hfiref0x/LightFTP_win.

# Changelog

Changelog available at Bin/changelog.txt

# Authors

(c) 2007 - 2024 LightFTP Project
