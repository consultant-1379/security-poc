#!/bin/bash

# env: NAMESPACE

echo "CREDM CONTROLLER LISTENER JOB starting ..."
echo "namespace : "$NAMESPACE

python3 /credm/src/secretListener.py

echo "end of CREDM CONTROLLER POST-INSTALL JOB"




