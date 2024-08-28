
#!/bin/bash

#
# this script delete md5 field from secret and cause restart of service
#

echo "reset : <servicename> (opt)<namespace> "

if [ -z "$1" ]
  then
    echo "No argument supplied"
	exit 1
fi
servicename=$1

 namespace="default"
if [ -n "$NAMESPACE" ]
  then
    namespace=$NAMESPACE
fi
if [ -n "$2" ]; then
    namespace=$2
   #echo namespace=$namespace
fi

controllername="eric-enm-credm-controller"
if [ -n "$CONTROLLER_NAME" ]
  then
    controllername=$CONTROLLER_NAME
fi

controllerport=5001
if [ -n "$REST_PORT" ]
  then
    controllerport=$REST_PORT
fi

echo " --------------------"
echo " reset certificates for service $servicename on namespace $namespace"
echo "       controllername= $controllername controllerpost=$controllerport"
echo " --------------------"
echo ""

# check if service exists
echo " --------------------"
echo "check servicename list"
servicelist=$(curl ${controllername}:${controllerport}/getServicesListWithCertificates)
echo "services="$servicelist
res=$(echo $servicelist | grep "\"$servicename\"" | wc -l)
if [[ $res == 0 ]]; then
   echo "$servicename not found in service list"
   exit 1
fi

# find certreq secret name
echo " --------------------"
echo "check certreq secrets"
secretname=$(kubectl get secret --selector=serviceName=$servicename -n $namespace | grep certreq | awk '{print $1}')

echo "secrets name = $secretname"
res=$(echo $secretname | grep $servicename | wc -l)
if [[ $res == 0 ]]; then
   echo "error in secret name"
   exit 1
fi

# execute
echo " --------------------"
echo "start reset secret and restart service"
TIMESTAMP1=`date +%Y-%m-%d:%H:%M:%S`
echo $TIMESTAMP1

# patch secret 
echo "reset MD5 field in secrets"
kubectl patch secret $secretname -p="{\"data\":{\"certReqMD5\": \"\"}}" -v=1 -n $namespace

# call credm controller simulation an upgrade
echo "call certrequest"
res=$(curl ${controllername}:${controllerport}/certrequest/$servicename)
echo $res
echo "end of procedure"
TIMESTAMP2=`date +%Y-%m-%d:%H:%M:%S`
echo $TIMESTAMP2
echo " --------------------"

check=$(echo $res | grep "NOT OK" | wc -l)
if [[ $check != 0 ]]; then
   echo "error execution of certRequest: $res"
   exit 1
fi
exit 0



