[![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2FLightFTP&countColor=%23263759&style=flat)](https://visitorbadge.io/status?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2FLightFTP) [![Build status](https://ci.appveyor.com/api/projects/status/0mvll9a7emrqo0a7?svg=true)](https://ci.appveyor.com/project/hfiref0x/lightftp)

# LightFTP
* Small x86-32/x64 FTP Server

# System Requirements

* x86-32/x64 POSIX-compliant OS, e.g. Linux.
* x86-32/x64 Windows 7/8/8.1/10 with Cygwin (see Build section of this README).
* No admin/root privileges required. The FTP server must be allowed in the firewall.

# Configuration

Stored in `fftp.conf` file, contains a configuration section named `ftpconfig` and a number of sections describing users and their privileges. 

#### [ftpconfig]

      port

Port number to bind the server to.
Default: 21

      maxusers

Maximum number of connections to the server that can be established simultaneously.
Default: 1

      interface

Interface IP to bind to. Use 0.0.0.0 to listen on any available interface.
Default: 127.0.0.1

      external_ip

If you are running the server behind a NAT, it is a good idea to put your real IP here.
This will help clients to establish data connections.
Default: 0.0.0.0

      local_mask

IP mask for local network.
This will help the server to distinguish between local and Internet clients.
Default: 255.255.255.0

      minport
      maxport

Port range for data connections. You can use it to configure port forwarding on your gateway device.
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

Password to decrypt the private key.

      keepalive

Send keepalive packets (some NATs may require this).
Default: 0 (disabled)

      follow_symlinks

Allow following symbolic links. When enabled, the server will follow symbolic links and treat them as regular files/directories.
Default: 0 (disabled)

# User Sections

Note for "accs" field:

      banned

Not allowed to log in.

      readonly

Just read directories and download files.

      upload

Create new directories, store new files. Append, rename, and delete are disabled.
      
      admin

All features enabled.

Note for "pswd" field:
`pswd=*` means "any password matches".

Example of configuration file can be found in the `src` directory as `fftp.conf`.

# Build 

* LightFTP comes with full source code, written in C.
* In order to build from source in Windows, you need a Cygwin environment (https://www.cygwin.com/) with GNU make, gnutls, and pthreads packages installed. Also, make sure the Cygwin bin folder is set in the system-wide PATH variable (e.g. `PATH=SomeOfYourOtherValues;C:\Cygwin\bin;C:\Cygwin\usr\bin`). To build the executable, run the `make` command in the `Release` directory.
* In order to build from source in Linux, you need the GCC C compiler. Run the `make` command in the `Release` directory. LightFTP uses GnuTLS, make sure you have headers (`libgnutls-dev` or `gnutls-dev`) installed.
* For debug builds with AddressSanitizer, run `make` in the `Debug` directory. ASAN helps detect memory errors and undefined behavior during development.

### Example for Linux Mint/Ubuntu

You need GCC and Make installed. If they are not installed, you can install them as part of the build-essential package:

      sudo apt install build-essential
      
LightFTP uses the GnuTLS library. It needs to be installed before compiling LightFTP. To install it, open terminal and use:

      sudo apt install gnutls-dev
	  
or if this doesn't work, try:

      sudo apt install libgnutls28-dev  
      
You can download the source from https://github.com/hfiref0x/LightFTP/releases or use git. 

In case you want to use git and git is not installed, install it first:

      sudo apt install git
      
Next, use the following:

      git clone https://github.com/hfiref0x/lightftp
      cd lightftp/src/Release
      make fftp

For debug build with AddressSanitizer:

      cd lightftp/src/Debug
      make fftp

To run with ASAN enabled:    	    	
		      
      ASAN_OPTIONS=abort_on_error=1,strict_string_checks=1,detect_stack_use_after_return=1,handle_segv=1,allow_user_segv_handler=1 ./LightFTP/src/Release/fftp ./LightFTP/data/fftp.conf
      
The resulting binary is `fftp`. Next, set up the ftp config. Example config file is `data/fftp.conf`. Set port, accounts, path to log file (optionally, if you need it), path to certificates if you want to use them, etc.

# Old Windows Version

Since 2.2, the old unmaintained Windows version has been moved to a separate archive repository: https://github.com/hfiref0x/LightFTP_win.

# Changelog

Changelog available at `data/changelog.txt`.

# Authors

(c) 2007 - 2025 LightFTP Project
