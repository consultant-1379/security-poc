
echo "helm commands: start | stop | status | upgrade (namespace)"

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
  helm3 install myservice chart/simpleservice/ -f localEnv.yaml -n $namespace
  helm3 status myservice -n $namespace
fi

#to start service:
#--------------------
if [ $1 = "upgrade" ]; then
  echo "----------"
  echo "upgrade helm"
  echo "----------"
  helm3 upgrade myservice chart/upgrade/ -f localEnv.yaml -n $namespace
  helm3 status myservice -n $namespace
fi

#to check service:
#--------------------
if [ $1 = "status" ]; then
  echo "----------"
  echo "helm status"
  echo "----------"
  helm3 status myservice -n $namespace
  kubectl get pods -n $namespace 
fi

#to remove service:
#--------------------
if [ $1 = "stop" ]; then
  echo "----------"
  echo "stop helm"
  echo "----------"
  helm3 delete myservice -n $namespace
  for i in $(kubectl get job -n $namespace | grep 'myservice' | awk '{print $1}'); do kubectl delete pvc $i -n $namespace; done
  for i in $(kubectl get pvc -n $namespace | grep 'myservice' | awk '{print $1}'); do kubectl delete pvc $i -n $namespace; done
fi

