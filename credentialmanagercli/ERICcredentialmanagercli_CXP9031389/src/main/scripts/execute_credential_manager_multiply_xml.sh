#!/bin/bash

XMLS_LOCATION=$1
FORCE_OPTION=$2
CRED_M=/opt/ericsson/ERICcredentialmanagercli/bin/credentialmanager.sh
EXIT=0
COUNT=1
INCREMENT=1

for entry in "$XMLS_LOCATION"/*.xml
do
	echo "[${COUNT}]================================================================================================="
	echo "====================================== Executing command  =========================================="
	echo "[INFO ] Executing...: "  ${CRED_M} -i -x "$entry" "$FORCE_OPTION"
	${CRED_M} -i -x "$entry" "$FORCE_OPTION"
	if [ $? -ne 0 ]
	then
		EXIT=1
		echo "[ERROR] Fail to execute the command. Look at the log for further information."
	else
		echo "[INFO ] Command executed successfully."
	fi
	echo "================================= Command Execution Finished ======================================="
	echo ""
	COUNT=$(($COUNT+$INCREMENT))
done
	
exit ${EXIT}