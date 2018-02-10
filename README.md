# LightFTP
* Small x86-32/x64 FTP Server

# System Requirements

* x86-32/x64 POSIX compliant OS, e.g. Linux.
* x86-32/x64 Windows Vista/7/8/8.1/10 with Cygwin (see Build section of this readme).
* No admin/root privileges required. FTP server must be allowed in firewall.

# Configuration

Stored in fftp.conf file, contain configuration section named ftpconfig and number of sections describing users and their privileges. 

#### [ftpconfig]

##### port
Port number to bind the server to.
Default: 21

##### maxusers
Maximum connections count to the server, that can be established simultaneously.
Default: 1

##### interface
Interface IP to bind to. Use 0.0.0.0 to listen on any available interface.
Default: 127.0.0.1

##### external_ip
If you running the server behind a NAT, it is a good idea to put your real IP here.
This will help clients to establish data connections.
Default: 0.0.0.0

##### local_mask
IP mask for local network.
This will help the server to distinguish between local and Internet clients.
Default: 255.255.255.0

##### minport
##### maxport
Port range for data connections. You can use it to configurate port forwarding on your gateway device.
Default: 1024..65535

##### logfilepath
Full path with file name for a log file. Comment or delete it to disable logging.
Default: disabled

##### CATrustFile
It is recommended to leave this option as it is (/etc/ssl/certs/ca-certificates.crt)

##### ServerCertificate
Path to your SSL certificate. Accepted format is x509 ASCII PEM.

##### Keyfile
Path to PEM private key file for your certificate.

##### KeyfilePassword
Password to decrypt private key.

# User sections

Note for "accs" field:

##### banned 
not allowed to log in

##### readonly
just read directories and download files

##### upload
creating new directories, store new files. Append, rename and delete disabled.

##### admin
all the features enabled.

Note for "pswd" field:
pswd=* means "any password is match"

Example of configuration file can be found in Source directory as fftp.conf.

# Build 

* LightFTP comes with full source code, written in C;
* In order to build from source in Windows you need Cygwin environment (https://www.cygwin.com/) with GNU make, gnutls and pthreads packages installed. Also make sure Cygwin bin folder is set in system wide PATH variable (e.g. PATH=SomeOfYourOtherValues;C:\Cygwin\bin;C:\Cygwin\usr\bin). To build executable run make command in the Release directory;
* In order to build from source in Linux you need GCC C compiler, run make command in the Release directory. LigthFTP uses GnuTLS, make sure you have headers (libgnutls-dev) installed;
* Old Windows Visual Studio source code and project files located in Source/Deprecated directory, in order to build from this source you need Microsoft Visual Studio 2013/2015 and later versions.

# Authors

(c) 2007 - 2018 LightFTP Project
