#!/bin/sh

# in case of removal or update we removed old cli logs 

if [  -e "/var/log/credentialmanager" ]; then
    find /var/log/credentialmanager -type f -exec rm -f {} \;
fi

# check if we are on updating phase 
# on removal one we will remove all logs files 
if [ "$1" -eq 0 ]; then 

    if [  -e "/var/log/enmcertificates" ]; then
	find /var/log/enmcertificates  -type f -exec rm -f {} \;
    fi


    if grep -q enmCertificatesLocal.sh "/etc/rc.local"; then
	sed -i '/enmCertificatesLocal.sh/d' /etc/rc.d/rc.local
    fi
else
# on updating removing only log files 
    find /var/log/enmcertificates   -type f \( -name '*' ! -name CredManagerCliShellPostinstall.log ! -name CredManagerCliDBShellPostInstall.log \) -exec \rm -f {} \;
fi

exit 0
