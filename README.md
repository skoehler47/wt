What is Wt ?
------------

Wt is a C++ library for developing web applications. It consists of:

- libwt, a widget/rendering library
- libwthttp, an (async I/O) HTTP/WebSockets server
- libwtfcgi, a FastCGI connector library (Unix)
- libwtisapi, an ISAPI connector library (Windows)
- libwttest, a test connector environment

It also contains a C++ ORM, which can be used in a web application
(obviously), but can also be used on its own:

- libwtdbo, a C++ ORM
- libwtdbopostgres, PostgreSQL backend
- libwtdbosqlite3, Sqlite3 backend
- libwtdbomysql, MySQL and MariaDB backend
- libwtdbomssqlserver, Microsoft SQL Server backend
- libwtdbofirebird, Firebird backend

For more information, see [the homepage](http://www.webtoolkit.eu/wt
"Wt homepage").

Dependencies
------------

To build Wt from source you will need at least
[CMake](https://cmake.org/), [boost](http://www.boost.org),
and a C++ compiler like GCC, Clang or MSVC. See the
[minimum dependency versions](doc/MinimumDependencyVersions.md)
for an explanation about which versions Wt supports.

Optionally, you may want to add:

- [OpenSSL](https://www.openssl.org) for SSL and WebSockets support in
  the built-in httpd, the HTTP(S) client, and additional cryptographic
  hashes in the authentication module
- [Haru PDF library](http://libharu.org) which is used for painting to PDF
- [GraphicsMagick](http://www.graphicsmagick.org/) which is used for painting
  to PNG, GIF (on Windows, Direct2D can be used instead)
- [PostgreSQL](https://www.postgresql.org/) for the PostgreSQL Dbo backend
- [MySQL](https://www.mysql.com) or [MariaDB](https://mariadb.org/) for the MySQL Dbo backend
- An [ODBC driver](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)
  for the Microsoft SQL Server Dbo backend, and [unixODBC](http://www.unixodbc.org/) on Unix-like platforms
- [Firebird](http://www.firebirdsql.org/) for the Firebird Dbo backend
- [Pango](http://www.pango.org/) for improved font support in PDF and raster
  image painting. On Windows, DirectWrite can be used instead.
- [ZLib](https://zlib.net/) for compression in the built-in httpd.

For the FastCGI connector, you also need:

- [FastCGI development kit](http://www.fastcgi.com/): you need the
  C/C++ library (libfcgi++)

Building
--------

Generic instructions for [Unix-like
platforms](https://www.webtoolkit.eu/wt/doc/reference/html/InstallationUnix.html)
or [Windows
platforms](https://www.webtoolkit.eu/wt/doc/reference/html/InstallationWindows.html).

Bug Reporting
-------------

Bugs can be reported here
http://redmine.webtoolkit.eu/projects/wt/issues/new

Security Issue Reporting
------------------------

We value the security of our users and take all vulnerability reports seriously. By reporting security vulnerabilities, you help us ensure the continued security and reliability of Wt.

Please report vulnerabilities privately to the Wt security team. Public disclosure of a vulnerability before it has been addressed could put users at risk. Send your vulnerability report to [wt-security@emweb.be](mailto:wt-security@emweb.be). We will investigate each report.

We will publicly disclose the vulnerability in the change log when a patch or update has been released.

While we do not offer a formal bug bounty program, we appreciate the efforts of security researchers who help us improve the security of Wt. We will acknowledge and credit responsible disclosures in our release notes and security advisories, unless you prefer to remain anonymous.

Demos, examples
---------------

[The homepage](https://www.webtoolkit.eu/wt), itself a Wt application,
contains also [various examples](https://www.webtoolkit.eu/wt/documentation/examples).

License
-------

Wt is available under two licenses:

- the GNU General Public License, Version 2, with OpenSSL exception. Only version 2 of the GPL applies. See the [`LICENSE`](LICENSE) file for more information.
- a [commercial license](https://www.webtoolkit.eu/wt/license/Wt%20License%20Agreement.pdf), which does not require you to distribute the source code of your application. Request a quotation [online](https://www.webtoolkit.eu/wt/download) or contact sales@emweb.be for more information.

See [`doc/licenses.md`](doc/licenses.md) for an exhaustive list of the licenses
used by Wt, source code from external sources included in Wt
and common (optional) external dependencies.
