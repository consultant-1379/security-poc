
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
import os
import time
import threading
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.client import configuration
from kubernetes import watch


###########################################
###########################################
###########################################
def threadRest(nameService):

    print("Start Thread for: %s" % nameService, flush=True)
    ret = os.system("/credm/src/runRest.sh "+nameService)
    print("Stop Thread for: %s ret: %d" % (nameService, ret), flush=True)
    sys.stdout.flush()


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
    print("WATCH CERTREQUEST SECRETS")
    try:
        # to filter on certRequest secrets
        for event in w.stream(v1.list_namespaced_secret, namespace=name_space, label_selector="certRequest in (true)"):
            print("----- find event")
            secret = event['object']
            print("Event: %s %s" % (event['type'], secret.metadata.name), flush=True)
            serviceName = secret.metadata.labels["serviceName"]
            print("ServiceName: %s " % (serviceName))

            # test of thread
            x = threading.Thread(target=threadRest, args=(serviceName,))
            x.start()

            time.sleep(2)
            
    except Exception as e: # work on python 3.x
        print('exception: '+ str(e))

    w.stop()

    print("End test watch", flush=True)

#
# main
#
if __name__ == "__main__":
    print(" LISTENER")
    namespace = str(os.environ.get("NAMESPACE", "default"))
    print("namespace: %s"  % (namespace))
    watchLoop(namespace)
    print(" end LISTENER", flush=True)
