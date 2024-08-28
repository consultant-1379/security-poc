
while true
do
   echo "CHECK"
echo "simpleservice" + $(kubectl describe deployment simpleservice | grep "restartcnt")
echo "otherservice" + $(kubectl describe deployment otherservice | grep "restartcnt")
echo "mystatefulset" + $(kubectl describe statefulset mystatefulset | grep "restartcnt")
   kubectl get pods
   echo "---"
   sleep 2
done



