
#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  LISTENER                     #
#                               #
#################################


import sys
from os import environ as env
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.client import configuration
from kubernetes import watch



###########################################
###########################################
###########################################
def watchLoop(nameSpace):

    name_space = nameSpace
    print("TEST WATCH")

    # K8S API
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    w = watch.Watch()
        
    print("----")
    print("WATCH SECRETS")
    try:
        for event in w.stream(v1.list_namespaced_secret, namespace=name_space):
            print("Event: %s %s" % (event['type'], event['object'].metadata.name), flush=True)
            sys.stdout.flush()
    except Exception as e: # work on python 3.x
        print('exception: '+ str(e))

    w.stop()

    print("End test watch")
    sys.stdout.flush()

#
# main
#
print(" LISTENER")
namespace = str(env.get("NAMESPACE", "default"))
print("namespace: %s"  % (namespace))
watchLoop(namespace)
print(" end LISTENER")
