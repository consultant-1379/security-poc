
flagVerbose=false

myEcho() {
  if [ "$flagVerbose" == true ] ; then
    echo $1
  fi
}

myHelp() {
  myEcho "ms8ms9commands (verbose) GET | SET "
  myEcho " -------------"
  myEcho " GET [ALL | credmEnableState | cronWorkingState]"
  myEcho " SET credmEnableState [enabled | disabled | enabling]"
  myEcho " SET cronWorkingState [idle | working]"
  myEcho " -------------"
}

if [ -z "$1" ]
then
    flagVerbose=true
    myHelp
    exit 0
fi

if [ "$1" == "verbose"  ]
then
    echo "VERBOSE MODE"
    flagVerbose=true
    shift
fi

if [ "$NAMESPACE" == ""  ]
then
  NAMESPACE="default"
fi

myHelp
myEcho "namespace="$NAMESPACE

statesecretname="eric-enm-credm-controller-state"

if [ "$1" == "GET" ]
then

    if [ "$2" == "ALL" ]
    then
	fieldName1=credmEnableState
    	fieldState1=$(kubectl get secret $statesecretname --template={{.data.${fieldName1}}} -n $NAMESPACE | base64 -d)
    	myEcho "get Field: "$fieldName1" = "$fieldState1
	fieldName2=cronWorkingState
    	fieldState2=$(kubectl get secret $statesecretname --template={{.data.${fieldName2}}} -n $NAMESPACE | base64 -d)
    	myEcho "get Field: "$fieldName2" = "$fieldState2
	fieldState=$fieldState1" "$fieldState2
    else
    	fieldName=$2
    	myEcho " GET "$fieldName
    	fieldState=$(kubectl get secret $statesecretname --template={{.data.${fieldName}}} -n $NAMESPACE | base64 -d)
    	myEcho "get Field: "$fieldName" = "$fieldState
   fi
fi

if [ "$1" == "SET" ]
then
    fieldName=$2
    fieldState=$3
    myEcho " SET "$fieldName" "$fieldState

    fieldStateEnc=$(echo -n $fieldState | base64)
    res=$(kubectl patch secret $statesecretname -p="{\"data\":{\"${fieldName}\": \"$fieldStateEnc\"}}" -v=1 -n $NAMESPACE)
    myEcho "$res"
    fieldState=$(kubectl get secret $statesecretname --template={{.data.${fieldName}}} -n $NAMESPACE | base64 -d)
    myEcho "set Field: "$fieldName" = "$fieldState
fi

if [ "$flagVerbose" == false ] ; then
  echo $fieldState
fi

exit 0





