
echo "parameters (one|two) to choose the POD, [namespace) optional"

namespace="default"
if [ -n "$2" ]; then
   namespace=$2
   echo namespace=$namespace
fi

echo "exec pod "
podname=$1
if [ "$1" == "one" ]; then
	podname=$(kubectl get pods -l app=eric-enm-credm-controller --no-headers -o custom-columns=":metadata.name" -n $namespace | tail -n 1)
fi
if [ "$1" == "two" ]; then
	podname=$(kubectl get pods -l app=eric-enm-credm-controller --no-headers -o custom-columns=":metadata.name" -n $namespace | head -n 1)
fi
echo "podname="$podname
podIp=$(kubectl describe pod $podname | grep " IP:")
echo "IP:"$podIp
echo "to start : /credm/scripts/run.sh"
kubectl exec -it $podname -- bash

