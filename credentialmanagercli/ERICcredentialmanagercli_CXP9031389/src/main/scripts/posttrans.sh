
#posttrans scriptlet (using /bin/sh):

#
# If enmCertificates is still installed at the end of the transaction
# start the service
#
echo "start posttrans."
echo "start posttrans." > /var/log/posttrans.log
if [ -x /etc/init.d/enmCertificates ] ; then
    if [ $(/sbin/pidof systemd) ] ; then
        echo "run enmCertificates."
	# call direct script instead of service because SSO seems not start
        echo "run enmCertificates." >> /var/log/posttrans.log
        /opt/ericsson/ERICcredentialmanagercli/bin/enmCertificatesLocal.sh
        echo "after enmCertificates." >> /var/log/posttrans.log
	#/bin/systemctl start enmCertificates.service
    elif [ $(/sbin/pidof init) ] ; then
	# RHEL6 keep things like before: rc.local wil be launched
	#/sbin/service enmCertificates start
        echo "RHEL6 do nothing"
	echo "RHEL6 do nothing" >> /var/log/posttrans.log
    else
	echo "Error: Failed to find any services system."
        echo "Error: Failed to find any services system." >> /var/log/posttrans.log
    fi
# elcugem
else
   echo "enmCertificates not found"
   echo "enmCertificates not found" >> /var/log/posttrans.log
fi

exit 0

