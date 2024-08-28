#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#!/usr/bin/python

import os
import constants
from kubernetes import client, config

#
# readTextFile
#
def readTextFile(filename):
    with open(filename, "r") as file:
       fileText = file.read()
    return fileText


#
# findCredmControllerApiVersion
#
def findCredmControllerApiVersion():
   text = readTextFile(constants.CLI_API_VERSION_FILE)
   if constants.LOG_DEBUG_FLAG == True:
       print("content of version.properties file : " + text)        
   stringList = []
   stringList = text.split("=")
   return stringList[1]


#
# findSpsPodWithRightCredmApiVersion
#
def findSpsPodWithRightCredmApiVersion(apiversion):
   # TEMP NO API VERSION
   #label_selector = constants.POD_LABEL_CREDM_API_VERSION + " in ({apiVersion})"
   #label_selector = label_selector.format(apiVersion=apiversion)
   label_selector = "app in ("+constants.SPS_APP_LABEL+")"
   if constants.LOG_DEBUG_FLAG == True:
      print("label_selector used to look for SPS :" + label_selector)

   config.load_incluster_config()
   v1 = client.CoreV1Api()
   if constants.LOG_DEBUG_FLAG == True:
      print("Invoking K8S api to get sps pod with right api version")
   retList = v1.list_namespaced_pod(constants.NAMESPACE, label_selector=label_selector)
   if constants.LOG_DEBUG_FLAG == True:
      print("Number of SPS PODs : {} ".format(len(retList.items)))

   if constants.LOG_DEBUG_FLAG == True:
      print("Looking for a sps pod with all containers with ready (state) = True")
   
   foundPodReady = False 
   if len(retList.items) > 0:
      # look for a POD with state ready
      for item in retList.items:
         foundPodReady = True
         for counter in range(len(item.status.container_statuses)):
            # check state for container
            if item.status.container_statuses[counter].ready == False:
               foundPodReady = False
               continue
         if foundPodReady == True:
            break
            
   return foundPodReady

         
   

