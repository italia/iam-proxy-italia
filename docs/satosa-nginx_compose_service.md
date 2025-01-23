## satosa-nginx Compose service

This service run a container with the last version of [Docker official Alpine NGINX](https://hub.docker.com/_/nginx/) image. 
This container work as [uWSGI](https://en.wikipedia.org/wiki/UWSGI) proxy to [iam-proxy-italia](./iam-proxy-italia_compose_service.md) containers and serve static file like the discovery page.

### Environments
| Environment | from            | Default value | Description
| ----------- | --------------- | ------------- | -----------
| NGINX_HOST  | SATOSA_HOSTNAME | localhost     | Hostname in satosa virtualhost
| TZ          | TZ              | Europe/Rome   | Set Time Zone for the istance

### Volumes
| from           | to                    | mode | Description
| -------------- | --------------------- | ---- | ------------
| ./nginx/conf.d | /etc/nginx/conf.d     | ro   | this directory contain all NGINX virtualst, read [Virtual Sost section](#vitual-host) 
| ./nginx/certs  | /etx/nginx/certs      | ro   | This directory contain the https cerificates, read [Satosa Virtual Host section](#satosa-vitual-host)
| ./nginx/html   | /usr/share/nginx/html | ro   | This directory contain the html static file for default virtual host, read [Static files section](#static-files)

*All `from path` are relative to Docker-compose directory*

### Virtual Hosts
Default NGINX conf import the additional configurations from `/etc/nginx/conf.d/*.conf`. The Path `Docker-compose/nginx/conf.d` is mounted in `/etc/nginx/conf.d` of NGINX container. Each `*.conf` file present in these directory is included in the NGINX configuration.

In `Docker-compose/nginx/conf.d` is preconfigured the file `default.conf` with [Satosa Virtual Host][#satosa-vitual-host]. You can add more `.conf` file and more virtual host, buth generally is not clever.

#### Satosa Virtual host
The Satosa Virtual Host listen exclusively on port 443 over protocol https.
The HTTPS protocol il limited at TLS1.3.
The older version of TLS and SSL are denyed

NGINX configuration accept configurations from environments. In the default configuration the `server_name` is definied with with `$NGINX_HOST` env. If is not present this variable, Docker Compose assign `localhost` as `NGINX_HOST` value.

TLS certificates will be searched in:
* `ssl_certificate /etc/nginx/certs/proxy_local.pem` - public certificate
* `ssl_certificate_key /etc/nginx/certs/proxy_local.key` - private key

On default the directory `Docker-compose/nginx/certs` is mounted on `/etc/nginx/certs`.
An self signed certificate for server name `localhost` is persent in the certs directory. To public the host you must overwrite these file with a valid certificate for you server name.

The virtual host root is set on `/usr/share/nginx/html`, the `Docker-compose/nginx/html` path is mounted over this directory.
To update the static file you must edit the files in `Docker-compose/nginx/html` path.

For security are added these header key
* `X-Frame-Options "DENY"` to block the IFRAME
* `X-Content-Type-Options nosniff` prevent mime type sniffing
* `X-XSS-Protection "1; mode=block"` prevents some categories of XSS attacks
* `X-Robots-Tag none` crawler are not welcome

`location @satosa` contain all information to send and get data from iam-proxy-italia uWSGI server.
The default configuration set `iam-proxy-italia:10000` as reverse uWSGI proxy destination.
This permits to balance the connection with multiple iam-proxy-italia instance.

Satosa Virtual Host use the `try_files` directive to send the request on the proxy.
The proxy test if the request is sended to a existent file. If the file not exists send the request to @satosa location. On detail:
1. Test if the request is a existent directory with a `index.html` file. Example: if the request is `/pippo` NGINX try to serve `/usr/share/nginx/html/pippo/index.html`
2. Test if  exists a file with the request path. Example: if request is `/pippo/pluto.html`, NGINX try to serve `/usr/share/nginx/html/pippo/pluto.html`
3. Send the request to `@satosa` location

### Insights
* For more details and example on NGINX satosa virtual host read [satosa-vitual-host doc](./satosa-virtual-host.md)
* For more details on iam-proxy-italia docker compose profiles read [docker-compose-profiles page](./docker-compose-profiles.md)

