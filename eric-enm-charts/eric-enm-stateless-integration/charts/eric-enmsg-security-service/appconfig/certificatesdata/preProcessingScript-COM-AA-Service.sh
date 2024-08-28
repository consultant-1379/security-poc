#!/bin/bash

# TEST EXECUTION SCRIPT

GLOBAL_PROPERTIES="/ericsson/tor/data/global.properties"
CREDM_DATA_XML="/ericsson/credm/data/xmlfiles/COM-AA-Service_CertRequest.xml"
CORRECT_IP=""
CORRECT_IP6=""
CORRECT_FALLBACK_IP=""
CORRECT_FALLBACK_IP6=""
IP_ADDR_COUNT=0

echo "EXECUTION PRE-START SCRIPT for COM-AA-Service_CertRequest.xml"
now=$(date +"%T")
echo "Current time : $now"
echo "-------------------"

# READ FROM GLOBAL PROPERTIES
echo "check global.properties"
if [ -f "$GLOBAL_PROPERTIES" ]; then

	CORRECT_IP="$(grep svc_CM_vip_ipaddress ${GLOBAL_PROPERTIES} | cut -d= -f2 | sed 's/\/[0-9]*$//')"
        echo "svc_CM_vip_ipaddress value from $GLOBAL_PROPERTIES : $CORRECT_IP"
        if [ -z "$CORRECT_IP" ]; then
                echo "svc_CM_vip_ipaddress not found in $GLOBAL_PROPERTIES"
        else
		IP_ADDR_COUNT=$((IP_ADDR_COUNT+1))	
	fi

	CORRECT_IP6="$(grep svc_CM_vip_ipv6address ${GLOBAL_PROPERTIES} | cut -d= -f2 | sed 's/\/[0-9]*$//')"
        echo "svc_CM_vip_ipv6address value from $GLOBAL_PROPERTIES : $CORRECT_IP6"
        if [ -z "$CORRECT_IP6" ]; then
                echo "svc_CM_vip_ipv6address not found in $GLOBAL_PROPERTIES"
	else
               	IP_ADDR_COUNT=$((IP_ADDR_COUNT+1)) 
        fi

	CORRECT_FALLBACK_IP="$(grep svc_FM_vip_ipaddress ${GLOBAL_PROPERTIES} | cut -d= -f2 | sed 's/\/[0-9]*$//')"
        echo "svc_FM_vip_ipaddress from $GLOBAL_PROPERTIES : $CORRECT_FALLBACK_IP"
        if [ -z "$CORRECT_FALLBACK_IP" ]; then
                echo "svc_FM_vip_ipaddress not found in $GLOBAL_PROPERTIES"
        else
                IP_ADDR_COUNT=$((IP_ADDR_COUNT+1))
        fi

	CORRECT_FALLBACK_IP6="$(grep svc_FM_vip_ipv6address ${GLOBAL_PROPERTIES} | cut -d= -f2 | sed 's/\/[0-9]*$//')"
        echo "svc_FM_vip_ipv6address from $GLOBAL_PROPERTIES : $CORRECT_FALLBACK_IP6"
        if [ -z "$CORRECT_FALLBACK_IP6" ]; then
                echo "svc_FM_vip_ipv6address not found in $GLOBAL_PROPERTIES"
	else
                IP_ADDR_COUNT=$((IP_ADDR_COUNT+1))
        fi

	if [ $IP_ADDR_COUNT -eq 0 ]; then
		echo "ZERO ip addresses found in $GLOBAL_PROPERTIES ... NOT OK ... exit"
		exit 1
	else
		echo "$IP_ADDR_COUNT ip addresses found in $GLOBAL_PROPERTIES ... OK"
	fi

else
        echo "$GLOBAL_PROPERTIES NOT FOUND"
        exit 1
fi

# CHECK THE PRESENCE of XML FILE AND UPDATE IT
echo "check and update COM-AA-Service_CertRequest.xml"

if [ -f "$CREDM_DATA_XML" ]; then

        echo "Updating $CREDM_DATA_XML"

	sed -i "s/##ipv4##/$CORRECT_IP/g" $CREDM_DATA_XML
        if [ $? -eq 0 ]; then
                echo "$CREDM_DATA_XML file updated succesfully for svc_CM_vip_ipaddress "
        else
            echo "$CREDM_DATA_XML file update FAILED for svc_CM_vip_ipaddress"
            exit 1
        fi

	sed -i "s/##ipv6##/$CORRECT_IP6/g" $CREDM_DATA_XML
        if [ $? -eq 0 ]; then
                echo "$CREDM_DATA_XML file updated succesfully for svc_CM_vip_ipv6address "
        else
            echo "$CREDM_DATA_XML file update FAILED for svc_CM_vip_ipv6address"
            exit 1
        fi

	sed -i "s/##ipv4_fallback##/$CORRECT_FALLBACK_IP/g" $CREDM_DATA_XML
        if [ $? -eq 0 ]; then
                echo "$CREDM_DATA_XML file updated succesfully for svc_FM_vip_ipaddress"
        else
            echo "$CREDM_DATA_XML file update FAILED for svc_FM_vip_ipaddress"
            exit 1
        fi 

	sed -i "s/##ipv6_fallback##/$CORRECT_FALLBACK_IP6/g" $CREDM_DATA_XML
        if [ $? -eq 0 ]; then
                echo "$CREDM_DATA_XML file updated succesfully for svc_FM_vip_ipv6address"
        else
            echo "$CREDM_DATA_XML file update FAILED for svc_FM_vip_ipv6address"
            exit 1
        fi

	sed -i "/<ipaddress><\/ipaddress>/d" $CREDM_DATA_XML
	if [ $? -eq 0 ]; then
                echo "$CREDM_DATA_XML file updated succesfully for <ipaddress>"
        else
            echo "$CREDM_DATA_XML file update FAILED for <ipaddress>"
            exit 1
        fi

	echo "$CREDM_DATA_XML file updated"

else
        echo "$CREDM_DATA_XML NOT FOUND"
        exit 1
fi

echo "END PRE-START SCRIPT for COM-AA-Service_CertRequest.xml"
exit 0
