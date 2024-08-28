# check access to variables
echo "--------------" 
echo "START RESTSERVER" 

cd /tmp
myhostname=$(hostname)
echo "hostname="$myhostname
python3 ./simpleRest3.py $myhostname


