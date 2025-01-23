## Nginx Virtual Host example

NGINX is quick and light web server.
Nginx is commonly used as frontend proxy for Satosa and his implementation iam-proxy-italia.
On follow some configuration examples.

### General information
* In all example in this doc, the discovery page and errors pages are served directly from NGINX as static file. In some case you can use uWSGI to serve static files, but normally isn't a good choice 
* For security reasons, all authentication connection, must be encrypted through HTTPS protocol
* For security reasons, https protocol use exclusively TLS1.3 to encrypt
* In all example we use `try_files` directive. With this directive you can test if the request is to a file or send there to a proxy location. In these examples:
* 1. Test if the request is a existent directory with a `index.html` file. If the request is `/pippo` NGINX try to serve `/usr/share/nginx/html/pippo/index.html`
* 2. Test if  exists a file with the request path. If request is `/pippo/pluto.html`, NGINX try to serve `/usr/share/nginx/html/pippo/pluto.html`
* 3. Send the request to `@satosa` location 
* `@satosa` location contain the proxy informations
* NGINX can read the system environments. This is useful to configure NGINX in docker.
### Docker host and uWSGI connection from network

#### Details
* The `server_name` is configured bu `$NGINX_HOST` environment. You change this with a static dns name
* In docker compose, if you create more replicas of a service, the service name is a pointment to all istances
* the certificates must be valid for the current host name
* The root path is `/usr/share/nginx/html` for docker but you can use your preferred path
* if you don't want personalize the errors pages you can remove the errors configurations
* @satosa location use the uWSGI protocol for proxy

#### satosa.conf
```
server {
    listen 443 ssl;
    server_name  $NGINX_HOST;
    ssl_protocols TLSv1.3;
    ssl_certificate /etc/nginx/certs/proxy_local.pem;
    ssl_certificate_key /etc/nginx/certs/proxy_local.key;

    # max upload size
    client_max_body_size 10m;

    # very long url for delega ticket
    large_client_header_buffers 4 16k;

    # deny iFrame
    add_header X-Frame-Options "DENY";

    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;

    root /usr/share/nginx/html;
    try_files $uri/index.html $uri @satosa;

    location @satosa {
      include /etc/nginx/uwsgi_params;
      
      uwsgi_pass iam-proxy-italia:10000;
      uwsgi_param Host $host;
      uwsgi_param X-Real-IP $remote_addr;
      uwsgi_param X-Forwarded-For $proxy_add_x_forwarded_for;
      uwsgi_param X-Forwarded-Proto $http_x_forwarded_proto;
      uwsgi_param HTTP_X_FORWARDED_PROTOCOL https;

      uwsgi_connect_timeout 75s;
      uwsgi_read_timeout 40;
      uwsgi_buffer_size          128k;
      uwsgi_buffers              4 256k;
      uwsgi_busy_buffers_size    256k;
      uwsgi_param SERVER_ADDR $server_addr;
    }

    error_page 404 /404.html;
    location = /404.html {
        root   /usr/share/nginx/html/errors;
    }

    error_page 403 /403.html;
    location = /403.html {
        root   /usr/share/nginx/html/errors;
    }

    # redirect server error pages to the static page /50x.html
    error_page 500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html/errors;
    }
}
```

#### proxy to socket
If you want use a local socket uwsgy server you must change the `uwsgi_pass` key:
```
uwsgy_pass unix:///opt/satosa-saml2/tmp/sockets/satosa.sock;
```
where `unix://` is the url protocol and `/opt/satosa-saml2/tmp/sockets/satosa.socks` is the socket path

#### nginx host log
If you want save the NGINX log for this host you can add this directive in the virtual host:
```
  access_log /var/log/nginx/satosa.access.log;
  error_log  /var/log/nginx/satosa.error.log error;
```
For docker instance the logs are sent to STDOUT and going in docker logs. This directive is normally not needed.

### Insights
* For more details on satosa-nginx compose service read [satosa-nginx_compose doc](./satosa-nginx_compose.md)
* For more details on iam-proxy-italia docker compose profiles read [docker-compose-profiles page](./docker-compose-profiles.md)
* For more details on NGINX try_files directive read the [official docs](https://www.slingacademy.com/article/nginx-try_files-directive-explained-with-examples/)
