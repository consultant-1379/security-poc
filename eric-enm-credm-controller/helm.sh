
echo "helm commands: start | stop | status (namespace)"

namespace="default"
if [ -n "$2" ]; then
   namespace=$2
   echo namespace=$namespace
fi

#to start service:
#--------------------
if [ $1 = "start" ]; then
  echo "----------"
  echo "start helm"
  echo "----------"
  #helm install chart/eric-enm-credm-controller/ -f localEnv.yaml --name credmcontroller
  helm3 install credmcontroller chart/eric-enm-credm-controller/ -f localEnv.yaml -n $namespace
  helm3 status credmcontroller -n $namespace
fi

#to check service:
#--------------------
if [ $1 = "status" ]; then
  echo "----------"
  echo "helm status"
  echo "----------"
  #helm status credmcontroller
  helm3 status credmcontroller -n $namespace
  kubectl get pods -n $namespace
fi

#to remove service:
#--------------------
if [ $1 = "stop" ]; then
  echo "----------"
  echo "stop helm"
  echo "----------"
  #helm delete credmcontroller --purge
  helm3 delete credmcontroller -n $namespace
  for i in $(kubectl get job -n $namespace | grep 'credm-controller' | awk '{print $1}'); do kubectl delete job $i -n $namespace; done
  for i in $(kubectl get pvc -n $namespace | grep 'credm-controller' | awk '{print $1}'); do kubectl delete pvc $i -n $namespace; done
  kubectl delete pvc "pvc-tordata" -n $namespace
  for i in $(kubectl get cm -n $namespace | grep 'credm-controller' | awk '{print $1}'); do kubectl delete cm $i -n $namespace; done
  kubectl delete cm "gpmap" -n $namespace
fi

