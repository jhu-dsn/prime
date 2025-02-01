#!/bin/bash

export CC="bclang"

for i in {1..4}
do
  cd Prime/src
  rand=$((RANDOM))
  make clean
  export CFLAGS="-frandom-seed=$rand -fdiversify"
  make
  cd ../..
  cp -r Prime Prime_$i
done
