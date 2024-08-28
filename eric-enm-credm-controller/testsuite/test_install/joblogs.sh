
echo "parameters (servicename) to choose the JOB, [namespace) optional"

namespace="default"
if [ -n "$2" ]; then
   namespace=$2
   echo namespace=$namespace
fi

echo "JOB LOG"
grepPod=${1}-certrequest-job
podname=$(kubectl get pods --no-headers -o custom-columns=":metadata.name" -n $namespace | grep $grepPod)
echo "podname="$podname
kubectl logs -f $podname -n $namespace


