#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  MAIN FUNCTION and            #
#  API ENTRYPOINTS              #
#                               #
#################################

# !flask/bin/python

from flask import Flask, jsonify
from flask import abort, request
import os, sys, json, base64, logging

# my constants and configuration
import constants
import common
import globalData
import restAPI
import k8sApiInterface
import xmlParser
import preprocXML
import restAPIms8ms9

app = Flask(__name__)


#
# REST SERVER
#

###########################################
###########################################
@app.route("/")
def route():
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received empty REST" )
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: end of empty REST")
    return restAPI.restList()

###########################################
###########################################
@app.route("/ping")
def ping():
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received ping REST" )
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: end of ping REST")
    return jsonify('pong')


###########################################
###########################################
@app.route('/certrequest/<string:service_name>', methods=['GET'])
@app.route('/certrequest/<string:service_name>/<string:date_in_seconds>/<string:timeout>', methods=['GET'])
def install(service_name, date_in_seconds=0, timeout=0):

    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received certrequest REST")
    result = "NOT OK"
    if common.stringSanitize(service_name):
        common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received certrequest REST for " + service_name)
        result = restAPI.certrequest(service_name, date_in_seconds, timeout)
        common.log(constants.LOG_LEVEL_INFO, result)
        common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: end of certrequest REST for " + service_name)
    else:
        common.log(constants.LOG_LEVEL_WARNING, f"install: sanitize input FAILED")
        result = "parameters not valid"
        abort(500, {'status': result})

    return jsonify(result)


###########################################
###########################################
#@app.route('/upgrade/<string:service_name>', methods=['GET'])
#def upgrade(service_name):
#    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received upgrade REST from " + service_name)
#    result = restAPI.upgrade(service_name)
#    common.log(constants.LOG_LEVEL_INFO, "----------------- end of upgrade REST for " + service_name)
#    return jsonify(result)


###########################################
###########################################
#@app.route('/rollback/<string:service_name>', methods=['GET'])
#def rollback(service_name):
#    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received rollback REST from " + service_name)
#    # try do an initial installation
#    result = restAPI.initialInstall(service_name)
#    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: end of rollback REST for " + service_name)
#    return jsonify(result)


###########################################
###########################################
@app.route('/periodicCheck/<string:service_name>', methods=['GET'])
def cron(service_name):

    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received periodicCheck REST")
    result = "NOT OK"

    if common.stringSanitize(service_name):
        common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received periodicCheck REST for " + service_name)
        result = restAPI.periodicCheck(service_name)
        common.log(constants.LOG_LEVEL_INFO, result)
        common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: end of periodicCheck REST for " + service_name)
    else:
        common.log(constants.LOG_LEVEL_WARNING, f"cron: sanitize input FAILED")
        result = "parameters not valid"
        abort(500, {'status': result})

    return jsonify(result)


###########################################
###########################################
@app.route("/getServicesListWithCertificates", methods=['GET'])
@app.route("/getServicesListWithCertificates/<string:forceString>", methods=['GET'])
def getServicesList(forceString=None):
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received getServicesListWithCertificates REST")
    forceFlag = False
    if forceString is not None:
        # sanitize
        if common.stringSanitize(forceString, ["force"]):
            forceFlag = True
        else:
            common.log(constants.LOG_LEVEL_WARNING, f"getServicesListWithCertificates: sanitize input FAILED")
            result = "parameters not valid"
            abort(500, {'status': result})

    serviceList = restAPI.servicesList(forceFlag)
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: end of getServicesListWithCertificates REST")
    return jsonify(serviceList)


###########################################
###########################################
#   MS8 MS9 rest commands
###########################################
###########################################

###########################################
###########################################
@app.route("/monitoring", methods=['GET'])
def getMonitoring():
    resultState = 'ERROR'

    # get status
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received GET monitoring REST")
    resultState = restAPIms8ms9.getMonitoringState()
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: end of GET monitoring REST")
    return jsonify({'status': resultState})


###########################################
###########################################
@app.route("/monitoring", methods=['PUT'])
def setMonitoring():
    resultState = 'ERROR'
    res = True

    # Set status
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received SET monitoring REST")

    # sanitize
    actionValue = request.args.get('action')
    if common.stringSanitize(actionValue, constants.ENABLE_ACTION.values()):
        common.log(constants.LOG_LEVEL_INFO, f"----------------- MAIN: action SET monitoring REST : {actionValue}")
        res, resultState = restAPIms8ms9.setMonitoringAction(actionValue)
        common.log(constants.LOG_LEVEL_INFO, f"----------------- MAIN: end of SET monitoring REST : {res} - {resultState}")
    else:
        common.log(constants.LOG_LEVEL_WARNING, f"monitoring: sanitize input FAILED")
        res = False
        resultState = "parameters not valid"

    # invalid state
    if res == False:
        abort(500, {'status': resultState})

    return jsonify({'status': resultState})


###########################################
###########################################
@app.route("/cronJobState/<string:action>", methods=['GET'])
def cronJobState(action):
    common.log(constants.LOG_LEVEL_INFO, "----------------- MAIN: received cronJobState REST")

    # sanitize
    if common.stringSanitize(action, constants.CRONJOB_ACTION.values()):
        common.log(constants.LOG_LEVEL_INFO, f"----------------- MAIN: end of cronJobState {action} REST")
        resultState = restAPIms8ms9.setCronjobState(action)
    else:
        common.log(constants.LOG_LEVEL_WARNING, f"cronJobState: sanitize input FAILED")
        resultState = "parameters not valid"

    return jsonify(resultState)


###########################################
###########################################
#   MS8 MS9 POC TEMP!!!!!! TO REMOVE BEFORE RELEASE
###########################################
###########################################
#@app.route("/credmEnableState", methods=['GET'])
#def getEnableState():
#    logging.info("----------------- MAIN: received getEnableState (ONLY FOR DEBUG) REST")
#    credmStateValue, cronStateValue, enableStateValue = restAPIms8ms9.getMonitoringState(allFlag=True)
#    logging.info(f"----------------- MAIN: end of monitoring get values (ONLY FOR DEBUG) REST")
#    return jsonify((credmStateValue, cronStateValue, enableStateValue))


###########################################
###########################################
#   MS8 MS9 POC TEMP!!!!!! TO REMOVE BEFORE RELEASE
###########################################
###########################################
#@app.route("/credmEnableState/<string:credmStateValue>/<string:cronStateValue>", methods=['GET'])
#def setEnableState(credmStateValue, cronStateValue ):
#    logging.info("----------------- MAIN: received monitoring set values ((ONLY FOR DEBUG)) REST")
#    res = restAPIms8ms9.__setControllerState(credmState=credmStateValue, cronState=cronStateValue)
#    credmStateValue, cronStateValue, enableStateValue = restAPIms8ms9.getMonitoringState(allFlag=True)
#    logging.info(f"----------------- MAIN: end of monitoring set values ((ONLY FOR DEBUG)) REST {res}")
#    return jsonify((credmStateValue, cronStateValue, enableStateValue))


#
# MAIN
#
# logging CONFIG
common.logConfig()

# k8s config
k8sApiInterface.k8sConfig()

# check state secret
restAPIms8ms9.checkControllerState()

if __name__ == "__main__":
    common.log(constants.LOG_LEVEL_INFO, "start Credm Controller")
    app.run(debug='True', host='0.0.0.0')
