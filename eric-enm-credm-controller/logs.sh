
echo "parameters (one|two|<pod name>) to choose the POD, [namespace) optional"

namespace="default"
if [ -n "$2" ]; then
   namespace=$2
   echo namespace=$namespace
fi

echo "LOG pod"
podname=$1
if [ "$1" == "one" ]; then
	podname=$(kubectl get pods -l app=eric-enm-credm-controller --no-headers -o custom-columns=":metadata.name" -n $namespace | tail -n 1)
fi
if [ "$1" == "two" ]; then
	podname=$(kubectl get pods -l app=eric-enm-credm-controller --no-headers -o custom-columns=":metadata.name" -n $namespace | head -n 1)
fi
echo "podname="$podname
podIp=$(kubectl describe pod $podname -n $namespace | grep " IP:")
echo "IP:"$podIp

kubectl logs -f $podname -n $namespace


