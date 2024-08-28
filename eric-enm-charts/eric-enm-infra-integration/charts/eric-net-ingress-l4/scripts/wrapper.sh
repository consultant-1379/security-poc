#!/bin/bash

set -o noclobber

LOCK_FILE="/scripts-exec/lock"
CAT=/bin/cat
count=0
# Max wait before executing script anyway without lock.
# terminationGracePeriod is 30s for ingress-l4.Hence, the value is set lower than 30.
MAX_WAIT=25

while [ $count -le $MAX_WAIT ]
do
  $CAT /dev/null > $LOCK_FILE
  return_code=$?
  if [ $return_code -ne 0 ]; then
      # File already exists. Wait for a second.
      sleep 1
  else
      # Execute the script/command passed as an argument to this wrapper script.
      "$@"
      script_return_code=$?
      rm -rf $LOCK_FILE
      exit "$script_return_code"
  fi
  let count=$count+1;
done
# Execute the script/command passed as an argument to this wrapper script anyway.
"$@"
