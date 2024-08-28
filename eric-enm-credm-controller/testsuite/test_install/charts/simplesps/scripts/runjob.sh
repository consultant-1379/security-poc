#!/bin/bash

# env: CONTROLLER_IP
# env: CONTROLLER_PORT

echo "simple service POST INSTALL HOOK"

echo "CONTROLLER_IP:"$CONTROLLER_IP
echo "CONTROLLER_PORT:"$CONTROLLER_PORT

res=-1
while [ $res -ne 0 ]
do
  echo "call Controller"
  curl -m 5 ${CONTROLLER_IP}:${CONTROLLER_PORT}
  res=$?
  echo $res
  sleep 5
done

echo "exit hook"







