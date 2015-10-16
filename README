Description
===========

A small library and CLI to perform OCSP lookups.

Motivation
==========

OpenSSL and GnuTLS too cumbersome for the simple use case.

Building
========

```
yum -y install gnutls gnutls-devel libcurl libcurl-devel autoconf libtool automake
autoreconf --install
libtoolize
automake --add-missing 
./configure
make
```

Packaging 
=========

(builds latest tag as RPMs for Centos/RHEL):

```
./package.sh
```

The packaging builds three packages:

 - libocsp: shared and static library
 - ocsp: CLI tool, depends on libocsp
 - libocsp-devel: development header files
 - ocsp source rpm: source of rpm package

CLI
===

The CLI tool takes as arguments

- The cert to check
- The path to a trusted CA cert that will be signing the OCSP request
- The path to the issuing CA certificate

In the following example, the CA cert is the same as the issuing CA.

```
[root@dev1 ~]# ocsp /root/cert.pem /root/cacert.pem /root/cacert.pem
Check success
```

Contributors
============

Mark Steele <mark@control-alt-del.org>
