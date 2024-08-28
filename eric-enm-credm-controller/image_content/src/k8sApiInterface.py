#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  KUBERNETES API INTERFACE     #
#                               #
#################################


import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.client import configuration
import constants
import common
import globalData


###########################################
# k8sConfig
#
# descr: initial configuration of k8s client api
# NOTE: set log to WARNING to avoid k8s api prints
#
# in: none
# out:  none)
##########################################
def k8sConfig():
    __k8sSetLogWARING()

def __k8sSetLogWARING():
    client.rest.logger.setLevel(logging.WARNING)
    
def __k8sSetLogDEBUG():
    client.rest.logger.setLevel(logging.DEBUG)


###########################################
# readPodsWithLabel
#
# descr: retrieve PODs with given label
#
# in: namespace (string)
# in: labelSelector (string)
# out:  returnList (json list)
###########################################
def readPodsWithLabel(nameSpace, labelSelector):
    label_selector = labelSelector
    name_space = nameSpace

    common.log(constants.LOG_LEVEL_DEBUG, "reading POD with label: %s" % labelSelector)

    # K8S API
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    # get pods with label
    retList = None
    try:
        retList = v1.list_namespaced_pod(name_space, label_selector=label_selector)
    except:
        common.log(constants.LOG_LEVEL_WARNING, "readPodsWithLabel : EXCEPTION")

    assert isinstance(retList, object)
    return retList


###########################################
# readSecretsWithLabel
#
# descr: retrieve SECRETs with given label
#
# in: namespace (string)
# in: labelSelector (string)
# out:  returnList (json list)
###########################################
def readSecretsWithLabel(nameSpace, labelSelector):
    label_selector = labelSelector
    name_space = nameSpace

    common.log(constants.LOG_LEVEL_DEBUG, "reading Secret with label: %s" % labelSelector)

    # K8S API
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    # retrieve secret from label
    retList = None
    try:
        retList = v1.list_namespaced_secret(name_space, label_selector=label_selector)
    except:
        common.log(constants.LOG_LEVEL_WARNING, "readSecretsWithLabel : EXCEPTION")

    assert isinstance(retList, object)
    return retList


###########################################
# readSecretData
#
# descr:  read the content of a secret (tls secret or cert. req. secret)
#
# in: secretName (string)
# in: namespace (string)
# out: secret (json format)
###########################################
def readSecretData(secretName, namespace):
    
    common.log(constants.LOG_LEVEL_DEBUG, "readSecretData : reading Secret with name: %s" % secretName)
    
    # K8S API
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    
    # retrieve secret data form secret name
    retSecret = None
    try:
        retSecret = v1.read_namespaced_secret(secretName, namespace)
    except:
        common.log(constants.LOG_LEVEL_WARNING, "readSecretData : EXCEPTION")
        
    # DEBUG
    if constants.LOG_DEBUG_FLAG:
        common.log(constants.LOG_LEVEL_DEBUG, "readSecretData : data type for " + secretName)
        common.log(constants.LOG_LEVEL_DEBUG, f"{type(retSecret)}")
        common.log(constants.LOG_LEVEL_DEBUG, f"{retSecret}")

    assert isinstance(retSecret, object)
    return retSecret


###########################################
# updateSecretData
#
# descr:  update the content of a secret
#         for example:
#                       -  certReqState for a cert secret
#                       -  tlsStoreLocation, tlsStoreType, tlsStoreData for a tls secret
#
# in: namespace (string)
# in: secret : the entire secret (modified data + unmodified data)
# out:  none
###########################################
def updateSecretData(secretName, namespace, secret):
    
    common.log(constants.LOG_LEVEL_DEBUG, "updateSecretData : updating Secret with name: %s" % secretName)
    
    # K8S API
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    # DEBUG
    if constants.LOG_DEBUG_FLAG:
        common.log(constants.LOG_LEVEL_DEBUG, "updateSecretData : data type for " + secretName)
        common.log(constants.LOG_LEVEL_DEBUG, f"{type(secret)}")
        common.log(constants.LOG_LEVEL_DEBUG, f"{secret}")

    # write secret data
    try:
        v1.patch_namespaced_secret(secretName, namespace, secret)
    except:
        common.log(constants.LOG_LEVEL_WARNING, "updateSecretData : EXCEPTION")
        return False

    return True


###########################################
# restartService
#
# descr:  restart a service (i.e. a "deployment object" or a "statefull_set" object)
#
# in: serviceName (string) : it is the service_name
# in: namespace (string)
# out: True/False
###########################################
def restartService(serviceName, namespace):
    
    # FOR DEBUG (it allows more prints from k8s api)
    #__k8sSetLogDEBUG()

    common.log(constants.LOG_LEVEL_DEBUG, "restartService : restart service with name: %s" % serviceName)
    
    # K8S API
    config.load_incluster_config()
    v1App = client.AppsV1Api()
    #common.log(constants.LOG_LEVEL_DEBUG,"restartService DEBUG: servicesList %s " % servicesList)

    # list deployments for name = serviceName
    isDeployment = False
    field_selector = "metadata.name={name}".format(name=serviceName)
    try:
        ret = v1App.list_namespaced_deployment(constants.NAMESPACE, field_selector=field_selector)
    except:
        common.log(constants.LOG_LEVEL_WARNING, "restartService : EXCEPTION on list_namespaced_deployment")
        return False

    common.log(constants.LOG_LEVEL_DEBUG, "restartService: Found {d} deployment(s) named '{n}''".format(
        d=len(ret.items), n=serviceName))
    # if any items present, means that service is a deployment
    if ret.items:
        isDeployment = True

    # retrieve deployment data or retrieve statefulSet data from serviceName
    if isDeployment == True: 
        common.log(constants.LOG_LEVEL_INFO,"restartService: service %s is a Deployment" % serviceName)
        try:
            deployData = v1App.read_namespaced_deployment(serviceName, constants.NAMESPACE)
        except:
            common.log(constants.LOG_LEVEL_WARNING, "restartService : EXCEPTION on read_namespaced_deployment")
            return False
    else:
        common.log(constants.LOG_LEVEL_INFO,"restartService: service %s is a StatefulSet" % serviceName)
        try:
            deployData = v1App.read_namespaced_stateful_set(serviceName, constants.NAMESPACE)
        except:
            common.log(constants.LOG_LEVEL_WARNING, "restartService : EXCEPTION on read_namespaced_stateful_set")
            return False
    
    # common processing for deployment data or stateful_set data           
    # look for the index of container that has the env var restartflag 
    numContainer = 0
    restartCntFound = False
    numRestartCnt = 0
    for idxContainer, container in enumerate(deployData.spec.template.spec.containers):
        envList = container.env
        #common.log(constants.LOG_LEVEL_DEBUG, f"{envList}")

        # look for restartcnt in the env list of this container
        for index, env in enumerate(envList):
            if env.name == constants.DEPLOYMENT_RESTARTCNT:
                numContainer = idxContainer
                numRestartCnt = index
                restartCntFound = True
    
    # if restartCntFound is False there is no need to increase value (it doent work anymore)
    if restartCntFound:
        envLabel = deployData.spec.template.spec.containers[numContainer].env[numRestartCnt]
        # increase value
        restartcnt = int(envLabel.value)
        restartcnt += 1
        common.log(constants.LOG_LEVEL_DEBUG,"restartService: restartcnt = " + str(restartcnt))
        envLabel.value = str(restartcnt)
        deployData.spec.template.spec.containers[numContainer].env[numRestartCnt] = envLabel
    else:
        # inject it in the first container
        common.log(constants.LOG_LEVEL_DEBUG,"restartService: add restartcnt field ")
        deployData.spec.template.spec.containers[numContainer].env.append({'name': constants.DEPLOYMENT_RESTARTCNT, 'value': '1'})
    
    # patch the deployment data or the stateful_set data
    if isDeployment == True:
        try:
            v1App.patch_namespaced_deployment(serviceName, constants.NAMESPACE, deployData)
        except:
            common.log(constants.LOG_LEVEL_WARNING, "restartService : EXCEPTION on patch_namespaced_deployment")
            return False
    else:
        try:
            v1App.patch_namespaced_stateful_set(serviceName, constants.NAMESPACE, deployData)
        except:
            common.log(constants.LOG_LEVEL_WARNING, "restartService : EXCEPTION on patch_namespaced_stateful_set")
            return False

    # DEBUG
    #__k8sSetLogWARING()
    
    return True
    
    
    
