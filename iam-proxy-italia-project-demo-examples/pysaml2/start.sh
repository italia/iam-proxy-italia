#!/bin/bash
CPATH=`pwd`
BIN=/usr/bin
PID=$$

function help () {
  echo "### Start Serice Provider ###"
  echo ""
  echo "Syntax: ./start.sh -u URL -p PATH -c"
  echo ""
  echo "-u URL is the idp metadata url, is mandatory the presence of an url or the metadata/idp.xml file "
  echo "-p PATH if present, copy the sp metadata on path"
  echo "-c clean log, certificates and metadata at end of script"
  echo ""
  echo "## Example ##"
  echo "$ ./start.sh -u https://idp.example.org/metadata -p /opt/satosa/metadata/sp" 
  echo "make new certificates, build a conf with idp metadata from idp.example.org and copy the sp metadata on satosa path"
  echo ""
  echo "## Files Path ##" 
  echo "pki/mykey.pem # sp private key" 
  echo "pki/myreq.csr # sp request key"
  echo "pki/mycert.pem # sp public key"
  echo "metadata/idp.xml # idp metadata"
  echo "metadata/sp.xml # sp metadata"
  echo ""
  echo "## other info ##"
  echo "server is run on localhost:9998"
  echo "for change it edit sp-wsgi/sp_conf.py"
  echo "log file is spx.log"
  abort
}

function abort () {
  echo 'operation aborted'
  if [ $CLEAN_DATA ]; then
    rm -rf ${CPATH}/pki ${CPATH}/metadata ${CPATH}/spx.log
  fi
  unset CPATH BIN DEST_PATH CLEAN_DATA
  kill -9 $PID
}

function check_idp () {
  if [ ! -f "${CPATH}/metadata/idp.xml" ]; then
    echo "No IDP metadata supplied"
    abort
  fi
}

function prepare () {
  poetry install
  mkdir -p ${CPATH}/pki ${CPATH}/metadata
}

function gen_cert () {
  if [ -f ${CPATH}/pki/mykey.pem -a -f ${CPATH}/pki/mycert.pem ]; then
    echo "Founded certificate"
  else
    openssl req -nodes -new -x509 -newkey rsa:2048 -days 3650 -keyout pki/mykey.pem -out pki/mycert.pem -subj "/C=IT/ST=Rome/L=Rome/O=test/OU=test/CN=localhost"
  fi
}

function gen_metadata () {
  make_metadata.py ${CPATH}/sp-wsgi/sp_conf.py > ${CPATH}/metadata/sp.xml
}

function copy_sp_metadata () {
  if [ "$DEST_PATH" ]; then
    cp ${CPATH}/metadata/sp.xml $DEST_PATH
  fi
}

trap abort EXIT
prepare

while getopts ":u:p:c" opt; do
  case ${opt} in
    u) wget $OPTARG -O ${CPATH}/metadata/idp.xml ;;
    p) DEST_PATH=$OPTARG;;
    c) CLEAN_DATA='true' ;;
    *) help ;;
  esac
done

check_idp
gen_cert
gen_metadata
copy_sp_metadata
python ${CPATH}/sp-wsgi/sp.py ${CPATH}/sp-wsgi/sp_conf
