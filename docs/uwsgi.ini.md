## uWSGI configuration example

Satosa proxy and his istance iam-proxy-italia are served by uWSGY. NGINX work as HTTP <-> uWSGI proxy to one or more iam-proxy-italia istance.

General information on uWSGI ini configuration:

* The uWSGI configuration Must be start with `[uwsgi]`
* Can be contain multiple arbitrary keys to generate structurated values, look `base` and `ckdir` keys as example.
* Must be contain the `socket` key with the file or the addres to expose the service
* can be contain `uid` and `gid` keys to define user and and group to execute the service
* If `uid` and `gid` keys are note defined, the service is started as current user and primary group
* must be contain `callable` or `module` key to run the correct application
* `ckdir` key define the derectory from the application must be executed
* if `pidfile` key is set with a file path, uWSGI on startup generate or update the file with the current Process ID (PID)
* You can add the `virtualenv` key with the path of [Python Virtual Env](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/#create-and-use-virtual-environments), uWSGI search the dipendences in his VirtualEnv
* If `harakiri` key is set with a number, the inactive process are restarted after the setted seconds
* You can add `pythonpath` key to set the Python runtime path
* If `virtualenv` and `pythonpath` keys are not set, uWSGI use the system default path


On follow we present some uWSGI configuration example for various situations.

### local instance with logrotate on localhost
#### important note:
* The project is located in `%(base)/%(project)` where `/opt` is `base` and `iam-proxy-italia` is `project`
* uWSGI server is runned with user: 'satosa' and group `satosa`. You can change this with the key `uid` and `gid`
* the VirtualEnv path is `%(base)/%(project)/env` or `/opt/iam-proxy-italia/env`
* Log are saved at `/var/log/uwsgi/%(project).log` or `/var/log/uwsgi/iam-proxy-italia.log`
* pid are saved at `/var/log/uwsgi/%(project).pid` or `/var/log/uwsgi/iam-proxy-italia.pid`
* the configuration is reloaded when change the date of `%(base)/%(project)/proxy_conf.yaml` or `/opt/iam-proxy-italia/proxy_conf.yaml`
* uwsgi server listen at 127.0.0.1:3002, only for local host! 

#### uwsgi.ini
```ini
[uwsgi]                
project     = iam-proxy-italia                                                                
base        = /opt
                                               
chdir       = %(base)/%(project)
                                               
uid         = satosa
gid         = satosa                          
                                               
socket      = 127.0.0.1:3002
master      = true                                                                             
processes   = 8 
# threads     = 2
                                                                                               
# sets max connections to
listen = 2048
                                               
wsgi-file   = %(base)/%(project)/env/lib/python3.10/site-packages/satosa/wsgi.py
callable = app                                                                                                                                                                                 
# se installato con pip non serve il plugin perchè embedded
# plugins    = python

# con virtualenv non serve
# pythonpath     = %(base)/%(project)/%(project)
virtualenv  = %(base)/%(project)/env

logto = /var/log/uwsgi/%(project).log
log-maxsize = 100000000
log-backupname = /var/log/uwsgi/%(project).old.log

log-master-bufsize = 128000

vacuum      = True

# respawn processes after serving ... requests
max-requests    = 512

# respawn processes taking more than takes more then ... seconds
harakiri    = 20

# avoid: invalid request block size: 4420 (max 4096)...skip
buffer-size=32768

pidfile     = /var/log/uwsgi/%(project).pid
touch-reload    = %(base)/%(project)/proxy_conf.yaml
```

### local instance on socket
#### important note
* The project is located in `%(base)/%(project)` where `/opt` is `base` and `iam-proxy-italia` is `project`
* uWSGI server is runned with user: 'satosa' and group `satosa`. You can change this with the key `uid` and `gid`
* the VirtualEnv path is `%(base)/%(project)/env` or `/opt/iam-proxy-italia/env`
* Log are saved at `/var/log/uwsgi/%(project).log` or `/var/log/uwsgi/iam-proxy-italia.log`
* pid are saved at `/var/log/uwsgi/%(project).pid` or `/var/log/uwsgi/iam-proxy-italia.pid`
* the configuration is reloaded when change the date of `%(base)/%(project)/proxy_conf.yaml` or `/opt/iam-proxy-italia/proxy_conf.yaml`
* uwsgi server listen in `/opt/iam-proxy-italia/tmp/sockets/satosa.sock`


#### uwsgi.ini
```ini
[uwsgi]
project     = iam-proxy-italia
base        = /opt

chdir       = %(base)/%(project)

uid         = satosa
gid         = satosa

socket      = %(base)/%(project)/tmp/sockets/satosa.sock
chmod-socket= 770

master      = true
processes   = 12
#threads     = 2

# set max connections to 1024 in uWSGI
listen = 5000

wsgi-file   = %(base)/apps/SATOSA/src/satosa/wsgi.py
callable = app
# se installato con pip non serve il plugin perchè embedded
#plugins    = python

# con virtualenv non serve
#pythonpath     = %(base)/%(project)/%(project)

virtualenv  = %(base)/django-pysaml2.env

logto = /var/log/uwsgi/%(project).log
log-maxsize = 100000000
log-backupname = /var/log/uwsgi/%(project).old.log

vacuum      = True

# respawn processes after serving ... requests
max-requests    = 1000

# respawn processes taking more than takes more then ... seconds
harakiri    = 20

# avoid: invalid request block size: 4420 (max 4096)...skip
buffer-size=32768

#env         = %(project).settings

pidfile     = /var/log/uwsgi/%(project).pid
touch-reload    = %(base)/%(project)/proxy_conf.yaml
stats           = 127.0.0.1:9193
stats-http      = True
```

### for docker container or simple local istance
#### Important note
* The project is located in `/satosa_proxy`
* uWSGI server is runned with user: 'root' and group `root`. You can change this with the key `uid` and `gid`
* Isn't user the virtualENV, uWSGY work with python system default 
* The log are printed on STDOUT
* pid are saved at `/satosa_proxy/%(project).pid`
* the configuration is reloaded when change the date of `/satosa_proxy/proxy_conf.yaml
* uwsgi server listen in `0.0.0.0:10000` and accept connection from all

#### uwsgi.ini
```
[uwsgi]
project     = iam-proxy-italia

chdir       = /satosa_proxy

uid         = satosa
gid         = satosa

socket      = 0.0.0.0:10000
master      = true
processes   = 8

# sets max connections to
listen = 2048

callable = app

log-master-bufsize = 128000
vacuum      = True

# respawn processes after serving ... requests
max-requests    = 512

# respawn processes taking more than takes more then ... seconds
harakiri    = 20

# avoid: invalid request block size: 4420 (max 4096)...skip
buffer-size=32768

pidfile     = /satosa_proxy/%(project).pid
touch-reload    = /satosa_proxy/proxy_conf.yaml
```
