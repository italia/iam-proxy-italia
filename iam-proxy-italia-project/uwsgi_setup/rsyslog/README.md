### Esempio di gestione dei log di satosa tramite RSyslog ###

#### Handler ####
L'hendler syslog invia i log al server syslog 127.0.0.1:514, con facility LOG_USER e socktype SOCK_DGRAM. 
Per personalizzare la connessione fare riferimento alla [documentazione](https://docs.python.org/3/library/logging.handlers.html#sysloghandler)
```
    syslog:
      class: logging.handlers.SysLogHandler
      level: INFO
      formatter: syslog
```
#### Formatter ####
Il formatter syslog antepone al messaggio i tag 'SATOSA', il nome del logger che invia il dato ed il livello dell'errore indicato
```
    syslog:
      format: "[SATOSA] [%(name)s] [%(levelname)s]: %(message)s"
```

#### Invio dei log ####
In proxy_conf.yaml impostare tutti i log verso l'handler syslog
```
  loggers:
    satosa:
      level: INFO
      handlers: [console,syslog]
      propagate: no
    saml2:
      level: ERROR
      handlers: [syslog]
      propagate: no
    satosa.frontends.saml2:
      level: DEBUG
      handlers: [syslog]
      propagate: no
    satosa.frontends.idpy_oidcop:
      level: DEBUG
      handlers: [syslog]
      propagate: no
    satosa.backends.saml2:
      level: DEBUG
      handlers: [syslog]
      propagate: no
    backends.spidsaml2:
      level: INFO
      handlers: [syslog]
      propagate: no
```
#### configurazione RSyslog ####
Tramite il server rsyslog (di default molte distribuzioni) è possibile salvare in posizioni differenti log specifici. 
In questo caso vengono salvati in un file tutti i lo di satosa ed in subdirectory i log dei frontend / backend.

Per attivare questa funzione basta creare un file di configurazione all'interno della direcotry `/etc/rsyslog.d`. 
Nel nostro caso il file `/etc/rsyslog.d/22-satosa.conf` invia i log di satosa nei vari file di log.
```
if $msg contains "[SATOSA]" then /var/log/satosa/current.log
if $msg contains "[SATOSA] [satosa.frontends.saml2]" then /var/log/satosa/frontends_saml2/current.log
if $msg contains "[SATOSA] [satosa.frontends.idpy_oidcop]" then /var/log/satosa/frontends_oidcop/current.log
if $msg contains "[SATOSA] [satosa.backends.saml2]" then /var/log/satosa/backends_saml2/current.log
if $msg contains "[SATOSA] [backends.spidsaml2]" then /var/log/satosa/backends_spidsaml2/current.log

```

#### Configurazione LogRotate ####
Tramite LogRotate è possibile archiviare e conservare per un tempo definito i log di sistema.
Nel nostro caso rinomineremo i log di ogni giorno con la data e li archivieremo compressi.

Per configurare LogRotate basta creare il file `/etc/logrotate.d/satosa` che archivierà e conserverà i log per 860 giorni
```
/var/log/satosa/current.log {
  daily
  rotate 860
  compress
  delaycompress
  notifempty
  create 640 syslog adm
  dateext
}
/var/log/satosa/frontends_saml2/current.log {
  daily
  rotate 860
  compress
  delaycompress
  notifempty
  create 640 syslog adm
  dateext
}
/var/log/satosa/frontends_oidcop/current.log {
  daily
  rotate 860
  compress
  delaycompress
  notifempty
  create 640 syslog adm
  dateext
}
/var/log/satosa/backends_saml2/current.log {
  daily
  rotate 860
  compress
  delaycompress
  notifempty
  create 640 syslog adm
  dateext
}
/var/log/satosa/backends_spidsaml2/current.log {
  daily
  rotate 860
  compress
  delaycompress
  notifempty
  create 640 syslog adm
  dateext
}
```
