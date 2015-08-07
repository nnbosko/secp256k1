#!/bin/bash

set -euo pipefail

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
mkdir -p ${DIR}/../{lib,dist}

if [ ! -e ${DIR}/../node_modules ] ; then
    echo "$(tput setaf 2)Installing node.js modules$(tput sgr 0)"
    (cd ${DIR}/.. ; lein npm install)
fi

if [ ! -e ${DIR}/../dist/bitauth.bundle.js ] ; then
    echo "$(tput setaf 2)Creating browser bundle for bitpay's bitauth$(tput sgr 0)"
    (cd ${DIR}/../lib ;
     [ -L bitauth.js ] || ln -s ../node_modules/bitauth/lib/bitauth.js bitauth.js)
    (cd ${DIR}/.. ;
     bash node_modules/bitauth/scripts/make-dist.sh)
fi

if [ ! -e ${DIR}/../dist/bitpay/bitauth.js ] ; then
    echo "$(tput setaf 2)Copying browser bundle to dist/bitpay/bitauth.js $(tput sgr 0)"
    mkdir -p ${DIR}/../dist/bitpay/
    sed -e 's/bitauth/BitAuth/g' ${DIR}/../dist/bitauth.bundle.js > ${DIR}/../dist/bitpay/bitauth.js
fi

if [ ! -e ${DIR}/../dist/bitpay/bitauth.min.js ] ; then
    echo "$(tput setaf 2)Copying minified browser bundle to dist/bitpay/bitauth.min.js $(tput sgr 0)"
    mkdir -p ${DIR}/../dist/bitpay/
    sed -e 's/bitauth/BitAuth/g' ${DIR}/../dist/bitauth.browser.min.js > ${DIR}/../dist/bitpay/bitauth.min.js
fi
