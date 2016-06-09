# certbot-cwebroot
Certbot plugin for clustered web servers

## Installation

* Install [certbot](https://certbot.eff.org/)
* Switch to the certbot virtualenv : 

  ```. ~/.local/share/letsencrypt/bin/activate```

* Install `certbot-cwebroot` :

  ```pip install certbot-cwebroot```

## Usage

This requires that you set up your webservers (all the servers that may be
queried by the ACME server for the challenge, that is) for the webroot method,
as described [here](https://certbot.eff.org/docs/using.html#webroot).

* Get yourself an SSH key pair and deploy it on your remote hosts under the
  same identity you will be using to run `certbot`.
* To use the local host as well as remote hosts `host2` and `host3`, run `certbot` like this :

  ```/path/to/certbot certonly --authenticator certbot-cwebroot:cwebroot -d www.example.com --certbot-cwebroot:cwebroot-path /var/www/html/letsencrypt/ --certbot-cwebroot:cwebroot-host host2 --certbot-cwebroot:cwebroot-host host3

  If you don't want the challenges to be hosted locally, you can use
  `--certbot-cwebroot:cwebroot-nolocal`.

* The certificate should be deployed in the usual directory (`/etc/letsencrypt`
  probably) on your localhost. As this follows the use cases for the webroot
  plugin (make no assumption on where the certificates should go), it is your
  job to deploy the obtained certificate to your target webservers.

## How it works

The SSH connection are made with [spur](https://pypi.python.org/pypi/spur),
which is a very convenient wrapper around [Paramiko](http://www.paramiko.org/).
Spur aims to run commands locally and remotely with the same interface, so
every file system operation that whas done in the `webroot` plugin with python
functions is now run with shell commands an binaries, namely :

* `chown`
* `mkdir`
* `rm`
* `rmdir`
* `sh`
* `stat`

I have tested this on an Ubuntu 14.04, and nowhere else.
