#!/bin/sh

echo ""
echo "[** bulding new configuration **]"
echo ""
make clean

if [ -f controller ] 
then
    make cclean
fi

if [ -f compute_hash ] 
then
    make compclean
fi

if [ -f decrypt ]
then
    make cdecrypt
fi

if [ -f encrypt ]
then
    make cencrypt
fi

echo ""
echo "[** building the kernel module **]"
echo ""
make 

echo ""
echo "[** building compute_hash **]"
echo "" 
make compute_hash

echo ""
echo "************************************"
echo "*   set the controller password    *"
echo "************************************"
echo ""

./compute_hash >> controller_options.h

echo ""
echo "[** building the decryption and encryption programs **]"
echo ""

make encrypt
make decrypt

echo ""
echo "[** building the controller **]"
echo ""
make controller

