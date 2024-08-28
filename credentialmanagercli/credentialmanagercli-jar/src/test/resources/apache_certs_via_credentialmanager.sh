#!/bin/bash
GREP=/bin/grep
SED=/bin/sed
CAT=/bin/cat
CP=/bin/cp
CRED_M=/opt/ericsson/ERICcredentialmanagercli/bin/credentialmanager.sh
OPENSSL=/usr/bin/openssl
RM=/bin/rm

#private key/certificate  location must be changed for a specific place in each blade(not shared in the network).
CERTS_LOC=$1
PRIVATE_KEY_LOC=$2

PREFIX_NAME=$3


CA_LOCATION=${CERTS_LOC}
CA_LOCATION=${CA_LOCATION/${PREFIX_NAME}.crt/}

APACHE_XML_LOCATION_TEMPLATE=/opt/ericsson/ERICcredentialmanagercli/conf/apache_certificate_template.xml
APACHE_XML_LOCATION=/opt/ericsson/ERICcredentialmanagercli/conf/apache_certificate.xml


${CP} -f ${APACHE_XML_LOCATION_TEMPLATE} ${APACHE_XML_LOCATION}


 
 #ip apache httpd
IP_ADDRESS_APACHE=`${CAT} /etc/hosts|${GREP} 'apache httpd'|${SED} 's/\([0-9.]*\).*/\1/'`

${SED} -i s/PRIVATE_KEY_LOCATION/${PRIVATE_KEY_LOC//\//\\/}/g ${APACHE_XML_LOCATION}

${SED} -i s/CERTS_LOCATION/${CERTS_LOC//\//\\/}/g ${APACHE_XML_LOCATION}
 
${SED} -i s/IP_ADDRESS/${IP_ADDRESS_APACHE}/g ${APACHE_XML_LOCATION}
 
${SED} -i s/HOST_APACHE/apache.vts.com/g ${APACHE_XML_LOCATION}

${SED} -i s/BLADE/$HOSTNAME/g ${APACHE_XML_LOCATION}

${SED} -i s/CA_LOCATION/${CA_LOCATION//\//\\/}/g ${APACHE_XML_LOCATION}



#Calling credential manager
${CRED_M} -i -f -xml ${APACHE_XML_LOCATION}


if [ $? -ne 0 ]
then

        ${OPENSSL} req -nodes -sha256 -newkey rsa:2048 -keyout ${PRIVATE_KEY_LOC} -out ${CA_LOCATION}ssoserverapache.csr -subj "/O=Ericsson/OU=ericssonTOR/CN=apache.vts.com" > /dev/null 2>&1
        ${OPENSSL} x509 -req -days 365 -in ${CA_LOCATION}ssoserverapache.csr -signkey ${PRIVATE_KEY_LOC} -out ${CERTS_LOC} > /dev/null 2>&1

        ${RM} -f ${CA_LOCATION}ssoserverapache.csr
		exit 0
fi
