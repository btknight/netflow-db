# netflow-db
Save netflow messages to a database for analysis.

Supports gathering Netflow records in v5 or v9 format. At the moment, only MySQL is supported as a back end database.

This enables users to perform pivot-table operations on the data in Excel.

Required:
* Python 3.5
* ipaddress module
* Oracle MySQL Connector

<pre>
usage: netflow.py [-h] [--daemonize] [--pidfile PIDFILE] [--dbuser DBUSER]
                  [--dbpassword DBPASSWORD] [--dbhost DBHOST]
                  [--dbname DBNAME] [--verbose] [--quiet]
                  port

Copy Netflow data to a MySQL database.

positional arguments:
  port                  Netflow UDP listener port

optional arguments:
  -h, --help            show this help message and exit
  --daemonize, -d       run in background
  --pidfile PIDFILE     location of pid file
  --dbuser DBUSER, -U DBUSER
                        database user
  --dbpassword DBPASSWORD, -P DBPASSWORD
                        database password
  --dbhost DBHOST, -H DBHOST
                        database host
  --dbname DBNAME, -D DBNAME
                        database name
  --verbose, -v         Verbosity of console messages
  --quiet, -q           Suppress console messages (only warnings and errors
                        will be shown
</pre>
