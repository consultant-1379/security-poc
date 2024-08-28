
#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

####################################################
#                                                  #
#  REST SERVER  MOCK OF CREDENTIALMANAGERCLI JAVA  #
#                                                  #
####################################################

import os, time
import shutil
import constants
import common

javaMockDelay = 25

###########################################
#
# mockInitalInstall
#
# in: none
# out: podList
###########################################
def mockInitalInstall():
    common.log(constants.LOG_LEVEL_INFO, "mockInitalInstall .... simulate JAVA run")
    for x in range(javaMockDelay):
        common.log(constants.LOG_LEVEL_INFO, "mock credentialmangercli java .... " + str(javaMockDelay+1-x))
        time.sleep(1)
    common.log(constants.LOG_LEVEL_INFO, "mock credentialmangercli java .... end")

    # ONLY FOR DEBUG : This copy makes __updateDataForCli detect a change in MD5 of cli keyStore/trustStore and
    #                  update tls secrets for cli.
    #                  Use this copy on mint where at the moment enmcertificates.sh is not executed.
    #                  Uncomment the relative import
    # two tls secrets for cli
    shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/credm/cli/data/certs/credmApiKS.JKS")
    shutil.copy("/credm/resources/test/jbossTS.JKS", "/ericsson/credm/cli/data/certs/credmApiTS.JKS")
    
    # ONLY FOR DEBUG : This copy makes __updateDataForService update tls secrets and cert. req. secrets
    #                  for the service.
    #                  Use this copy on mint where at the moment enmcertificates.sh is not executed.
    #                  Uncomment the relative import
    if os.path.exists("/ericsson/credm/district11/certs"):
        # cert. req. secret 1
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/credm/district11/certs/jbossKS.JKS")
        shutil.copy("/credm/resources/test/jbossTS.JKS", "/ericsson/credm/district11/certs/jbossTS.JKS")
    
        # DEBUG for UPGRADE
        shutil.copy("/credm/resources/test/jbossTS.JKS", "/ericsson/credm/district11/certs/jbossTS2.JKS")

    # cert. req. secret 2
    if os.path.exists("/opt/ericsson/com.ericsson.oss.services.security.accesscontrol.com-aa-service"):
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/opt/ericsson/com.ericsson.oss.services.security.accesscontrol.com-aa-service/keystore")
        shutil.copy("/credm/resources/test/jbossTS.JKS", "/opt/ericsson/com.ericsson.oss.services.security.accesscontrol.com-aa-service/truststore")
    # cert. req. secret 5
    if os.path.exists("/ericsson/cppaaservice/data/certs"):
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/cppaaservice/data/certs/CppAAFileSignerKeyStore.p12")

    # work with mscm/mskpirt service on minikube
    if os.path.exists("/ericsson/neconn/data/certs"):
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/neconn/data/certs/cert.p12")
        shutil.copy("/credm/resources/test/jbossTS.JKS", "/ericsson/neconn/data/certs/trustca_all.pem")
        
    # work with msnetlog service on minikube
    if os.path.exists("/ericsson/mediation/data/certs/"):
        shutil.copy("/credm/resources/test/jbossKS.JKS",  "/ericsson/mediation/data/certs/tlsnetconf.key")
        shutil.copy("/credm/resources/test/jbossKS.JKS",  "/ericsson/mediation/data/certs/tlsnetconf.cert")
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/mediation/data/certs/tlsnetconfCA.pem")
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/mediation/data/certs/tlshttpsconf.jks")
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/mediation/data/certs/tlshttpsconfCA.jks")

    # work with msfm service on minikube
    if os.path.exists("/ericsson/fault_management/cppalarmevent_resource_adapter/data/certs"):
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/fault_management/cppalarmevent_resource_adapter/data/certs/FMCerts.p12")
        shutil.copy("/credm/resources/test/jbossTS.JKS", "/ericsson/fault_management/cppalarmevent_resource_adapter/data/certs/trustca_all.pem")

    # work with cmserv service on minikube
    if os.path.exists("/ericsson/credm/data/certs"):
        shutil.copy("/credm/resources/test/jbossKS.JKS",  "/ericsson/credm/data/certs/jbossKS.JKS")
        shutil.copy("/credm/resources/test/jbossTS.JKS",  "/ericsson/credm/data/certs/jbossTS.JKS")

    # work with httpd service on minikube (container in a service)
    if os.path.exists("/etc/pki/tls/private"):
        shutil.copy("/credm/resources/test/jbossKS.JKS",  "/etc/pki/tls/private/ApacheCert.key")
    if os.path.exists("/etc/pki/tls/certs"):
        shutil.copy("/credm/resources/test/jbossKS.JKS",  "/etc/pki/tls/certs/ApacheCert.crt")

    # work with secserv service on minikube
    if os.path.exists("/ericsson/cert/data/certs"):
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/ericsson/cert/data/certs/secservKS.JKS")
        shutil.copy("/credm/resources/test/jbossTS.JKS", "/ericsson/cert/data/certs/secservTS.JKS")

    # work with remotedesktop service on minikube
    if os.path.exists("/opt/thinlinc/etc/tlwebaccess"):
        shutil.copy("/credm/resources/test/jbossKS.JKS", "/opt/thinlinc/etc/tlwebaccess/server.key")
        shutil.copy("/credm/resources/test/jbossTS.JKS", "/opt/thinlinc/etc/tlwebaccess/server.crt")


###########################################
#
# mockPeriodicCheck
#
# in: none
# out: podList
###########################################
def mockPeriodicCheck():
    common.log(constants.LOG_LEVEL_INFO, "mock credentialmangercli java PERIODIC CHECK ....pause to simulate JAVA run")
    for x in range(javaMockDelay):
        common.log(constants.LOG_LEVEL_INFO, "mock credentialmangercli java PERIODIC CHECK...." + str(javaMockDelay+1-x))
        time.sleep(1)
    common.log(constants.LOG_LEVEL_INFO, "mock credentialmangercli java....end")
       
    # ONLY FOR DEBUG : This copy makes __updateDataForCli detect a change in MD5 of cli keyStore/trustStore and
    #                  update tls secrets for cli.
    #                  Use this copy on mint where enmcertificates.sh is not executed.
    #                  Uncomment the relative import
    # Note : this copy is deliberately different from the corresponding one in the case of I.I
    #        to force a change in certificates done in I.I.
    #        first c.c. after the I.I. detects the change
    # two tls secrets for cli
    shutil.copy("/credm/resources/test/credmApiKS.JKS", "/ericsson/credm/cli/data/certs/credmApiKS.JKS")
    shutil.copy("/credm/resources/test/credmApiTS.JKS", "/ericsson/credm/cli/data/certs/credmApiTS.JKS")

    # ONLY FOR DEBUG : This copy makes __updateDataForService update tls secrets and cert. req. secrets
    #                  for the service.
    #                  Use this copy on mint where enmcertificates.sh is not executed.
    #                  Uncomment the relative import
    # Note : this copy is deliberately different from the corresponding one in the case of I.I
    #        to force a change in certificates done in I.I.
    #        first c.c. after the I.I. detects the change
    if os.path.exists("/ericsson/credm/district11/certs"):
        # cert. req. secret 1
        shutil.copy("/credm/resources/test/secservKS.JKS", "/ericsson/credm/district11/certs/jbossKS.JKS")
        shutil.copy("/credm/resources/test/secservTS.JKS", "/ericsson/credm/district11/certs/jbossTS.JKS")

    # cert. req. secret 2
    if os.path.exists("/opt/ericsson/com.ericsson.oss.services.security.accesscontrol.com-aa-service"):
        shutil.copy("/credm/resources/test/keystore", "/opt/ericsson/com.ericsson.oss.services.security.accesscontrol.com-aa-service/keystore")
        shutil.copy("/credm/resources/test/truststore", "/opt/ericsson/com.ericsson.oss.services.security.accesscontrol.com-aa-service/truststore")
    # cert. req. secret 5
    if os.path.exists("/ericsson/cppaaservice/data/certs"):
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/ericsson/cppaaservice/data/certs/CppAAFileSignerKeyStore.p12")

    # work with mscm/mskpirt service on minikube
    if os.path.exists("/ericsson/neconn/data/certs"):
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/ericsson/neconn/data/certs/cert.p12")
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/ericsson/neconn/data/certs/trustca_all.pem")
        
    # work with msnetlog service on minikube
    if os.path.exists("/ericsson/mediation/data/certs/"):
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12",  "/ericsson/mediation/data/certs/tlsnetconf.key")
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12",  "/ericsson/mediation/data/certs/tlsnetconf.cert")
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/ericsson/mediation/data/certs/tlsnetconfCA.pem")
        shutil.copy("/credm/resources/test/secservKS.JKS", "/ericsson/mediation/data/certs/tlshttpsconf.jks")
        shutil.copy("/credm/resources/test/secservTS.JKS", "/ericsson/mediation/data/certs/tlshttpsconfCA.jks")
    
    # work with msfm service on minikube
    if os.path.exists("/ericsson/fault_management/cppalarmevent_resource_adapter/data/certs"):
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/ericsson/fault_management/cppalarmevent_resource_adapter/data/certs/FMCerts.p12")
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/ericsson/fault_management/cppalarmevent_resource_adapter/data/certs/trustca_all.pem")

    # work with cmserv service on minikube
    if os.path.exists("/ericsson/credm/data/certs"):
        shutil.copy("/credm/resources/test/jbossKS.JKS",  "/ericsson/credm/data/certs/jbossKS.JKS")
        shutil.copy("/credm/resources/test/jbossTS.JKS",  "/ericsson/credm/data/certs/jbossTS.JKS")

    # work with httpd service (container in a service) on minikube
    if os.path.exists("/etc/pki/tls/private"):
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12",  "/etc/pki/tls/private/ApacheCert.key")
    if os.path.exists("/etc/pki/tls/certs"):
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12",  "/etc/pki/tls/certs/ApacheCert.crt")

    # work with secserv service on minikube
    if os.path.exists("/ericsson/cert/data/certs"):
        shutil.copy("/credm/resources/test/secservKS.JKS", "/ericsson/cert/data/certs/secservKS.JKS")
        shutil.copy("/credm/resources/test/secservTS.JKS", "/ericsson/cert/data/certs/secservTS.JKS")

    # work with remotedesktop service on minikube
    if os.path.exists("/opt/thinlinc/etc/tlwebaccess"):
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/opt/thinlinc/etc/tlwebaccess/server.key")
        shutil.copy("/credm/resources/test/CppAAFileSignerKeyStore.p12", "/opt/thinlinc/etc/tlwebaccess/server.crt")

    # ONLY FOR DEBUG : The creation of this file simulates the detection of the need to restart the service
    #                  on mint where enmcertificates.sh is not executed.
    if os.path.exists("/credm/resources/test/forceRestart"):
        common.writeTextFile(constants.CREDM_CONTROLLER_STATE_FILE, "")

