#!/bin/bash

if [ ! -d dante-1.4.1 ] || [ ! -d dante-1.4.1/configure ]; then
    rm dante-1.4.1 -rf
    wget https://www.inet.no/dante/files/dante-1.4.1.tar.gz -O dante-1.4.1.tar.gz || exit 1
    tar xzf dante-1.4.1.tar.gz || exit 1
fi
pushd dante-1.4.1
./configure && make -j4 && make install || exit 1
popd
cp tests/socksify/socks.conf /etc/ || exit 1
