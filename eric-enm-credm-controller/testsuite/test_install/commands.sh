
echo "TEST SUITE COMMANDS:"
echo "install | upgrade | backupgrade | delete | oneshotcronjob | ms8ms9job"
echo " "

 
# to install
if [ "$1" == "install" ]
then
	date > log.txt
	helm3 install eric-enm-test .  --wait --timeout 600s --debug >> log.txt
	date >> log.txt
fi


# upgrade to alternate simpleservice chart
if [ "$1" == "upgrade" ]
then
	mv charts/simpleservice/ forInstall/
	mv forUpgrade/simpleservice/ charts/
	date > log.txt
	helm3 upgrade eric-enm-test .  --wait --timeout 600s --debug >> log.txt
	date >> log.txt
fi

# upgrade to return to normal simpleservice chart
if [ "$1" == "backupgrade" ]
then
	mv charts/simpleservice/ forUpgrade/
	mv forInstall/simpleservice/ charts/
	date > log.txt
	helm3 upgrade eric-enm-test .  --wait --timeout 600s --debug >> log.txt
	date >> log.txt
fi


# delete the helm
if [ "$1" == "delete" ]
then
	helm3 delete eric-enm-test
fi

# create a job to run immediately a cron job
# (to be removed after completion)
if [ "$1" == "oneshotcronjob" ]
then
	kubectl create job --from=cronjob/eric-enm-credm-controller-cron-job eric-enm-credm-controller-cron-oneshot
	echo "to be deleted after completion with command"
	echo "	kubectl delete job eric-enm-credm-controller-cron-oneshot"
fi

# ms8ms9
if [ "$1" == "ms8ms9job" ]
then
	kubectl create job --from=cronjob/eric-enm-credm-controller-ms8ms9-cronjob eric-enm-credm-controller-ms8ms9-job
fi






