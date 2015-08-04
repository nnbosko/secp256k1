#!/bin/bash -x

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
mkdir -p ${DIR}/../{lib,dist}

if [ ! -e ${DIR}/../node_modules ] ; then
	(cd ${DIR}/.. ; lein npm install)
fi

if [ ! -e ${DIR}/../dist/bitauth.bundle.js ] ; then
   (cd ${DIR}/../lib ;
      [ -L bitauth.js ] || ln -s ../node_modules/bitauth/lib/bitauth.js bitauth.js)
   (cd ${DIR}/.. ;
      bash node_modules/bitauth/scripts/make-dist.sh)
fi

if [ ! -e ${DIR}/../target/classes/public/js/bitauth.bundle.js ] ; then
   mkdir -p ${DIR}/../target/classes/public/js/
   cp ${DIR}/../dist/bitauth.{browser.min,bundle}.js ${DIR}/../target/classes/public/js/
fi
