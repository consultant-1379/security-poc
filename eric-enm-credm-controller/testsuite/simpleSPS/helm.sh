
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
  helm3 install mysps ../test_install/charts/simplesps -n $namespace
  helm3 status mysps -n $namespace
fi

#to check service:
#--------------------
if [ $1 = "status" ]; then
  echo "----------"
  echo "helm status"
  echo "----------"
  helm3 status mysps -n $namespace
  kubectl get pods -n $namespace
fi

#to remove service:
#--------------------
if [ $1 = "stop" ]; then
  echo "----------"
  echo "stop helm"
  echo "----------"
  helm3 delete mysps -n $namespace
  #for i in $(kubectl get pvc -n $namespace | grep 'mysps' | awk '{print $1}'); do kubectl delete pvc $i -n $namespace; done
fi

