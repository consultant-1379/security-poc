
#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  REST SERVER                  #
#                               #
#################################

import common
import constants
import k8sApiInterface


# result state state
__resultStateDict = dict([
    ((constants .CREDMENABLE_STATE['ENABLED'], constants.CRONENABLE_STATE['IDLE']), constants.ENABLE_STATE['ENABLED']),
    ((constants .CREDMENABLE_STATE['ENABLED'], constants.CRONENABLE_STATE['WORKING']), constants.ENABLE_STATE['ENABLED']),
    ((constants .CREDMENABLE_STATE['DISABLED'], constants.CRONENABLE_STATE['IDLE']), constants.ENABLE_STATE['DISABLED']),
    ((constants .CREDMENABLE_STATE['DISABLED'], constants.CRONENABLE_STATE['WORKING']), constants.ENABLE_STATE['DISABLING']),
    ((constants .CREDMENABLE_STATE['ENABLING'], constants.CRONENABLE_STATE['IDLE']), constants.ENABLE_STATE['ENABLING']),
    ((constants .CREDMENABLE_STATE['ENABLING'], constants.CRONENABLE_STATE['WORKING']), constants.ENABLE_STATE['ENABLING'])
])


###########################################
# getMonitoringState
#
# descr: read values from CONTROLLER_STATE_SECRET
#
# in: all flag to return all values or only the enable state
# out:  result state
###########################################
def getMonitoringState(allFlag=False):

    common.log(constants.LOG_LEVEL_DEBUG, f"start getMonitoringState: allFlag {allFlag}")
    # read secret
    secret_data = k8sApiInterface.readSecretData(constants.CONTROLLER_STATE_SECRET_NAME, constants.NAMESPACE)
    # extract data
    credmEnableStateValueEnc = secret_data.data[constants.CONTROLLER_STATE_SECRET_CREDMSTATE_FIELD]
    cronWorkingStateValueEnc = secret_data.data[constants.CONTROLLER_STATE_SECRET_CRONSTATE_FIELD]
    # decode string
    credmEnableStateValue = common.decodeString(credmEnableStateValueEnc)
    cronWorkingStateValue = common.decodeString(cronWorkingStateValueEnc)
    # build result state
    resultState = __resultStateDict[(credmEnableStateValue, cronWorkingStateValue)]
    common.log(constants.LOG_LEVEL_DEBUG, f"getMonitoringState : credm: {credmEnableStateValue} cron: {cronWorkingStateValue} state : {resultState}  ")
    if allFlag == True:
        return credmEnableStateValue, cronWorkingStateValue, resultState
    return resultState


###########################################
# setMonitoringAction
#
# perform required action
#
# descr: perform required action from POST REST
#
# in: action
# out:  boolean, previous state
###########################################
def setMonitoringAction(actionValue):

    common.log(constants.LOG_LEVEL_INFO, f"start setMonitoringAction : actionValue {actionValue}")
    previousValue = getMonitoringState()
    resultOp = False
    # check value
    if actionValue in constants.ENABLE_ACTION.values():
        #
        # action=ENABLE
        #
        # accepted only if state=DISABLED
        # error if state=DISABLING
        if actionValue == constants.ENABLE_ACTION['ENABLE']:
            common.log(constants.LOG_LEVEL_DEBUG, "setMonitoringAction: action ENABLE")
            if previousValue != constants.ENABLE_STATE['DISABLING']:
                resultOp = True
                if previousValue == constants.ENABLE_STATE['DISABLED']:
                    resultOp = setControllerState(credmState=constants.CREDMENABLE_STATE['ENABLING'])
                    # perform all steps to manage transition from 'ENABLING' to 'ENABLED'
                    if resultOp:
                        goEnabled()
        #
        # action=DISABLE
        #
        # accepted only if state=ENABLED
        # error if state=ENABLING
        elif actionValue == constants.ENABLE_ACTION['DISABLE']:
            common.log(constants.LOG_LEVEL_DEBUG, " setMonitoringAction: action DISABLE")
            if previousValue != constants.ENABLE_STATE['ENABLING']:
                resultOp = True
                if previousValue == constants.ENABLE_STATE['ENABLED']:
                    resultOp = setControllerState(credmState=constants.CREDMENABLE_STATE['DISABLED'])
        #
        # action=RESET
        #
        # accepted in any state, reset state to ENABLED
        elif actionValue == constants.ENABLE_ACTION['RESET']:
            common.log(constants.LOG_LEVEL_DEBUG, " setMonitoringAction: action RESET")
            resultOp = setControllerState(credmState=constants.CREDMENABLE_STATE['ENABLED'])

    common.log(constants.LOG_LEVEL_DEBUG, f"setMonitoringAction result : {resultOp} {previousValue}")
    return resultOp, previousValue


###########################################
# setCronjobState
#
# received bu cronjob
#
# descr: perform required action
#
# in: action (start stop)
# out:  boolean
###########################################
def setCronjobState(actionValue):

    common.log(constants.LOG_LEVEL_INFO, f"start setCronjobState : actionValue {actionValue}")

    # read status
    credmStateValue, cronStateValue, enableStateValue = getMonitoringState(allFlag=True)
    if actionValue == constants.CRONJOB_ACTION['START']:
        # check if controller is in a valid state
        if credmStateValue in constants.VALID_STATE_FOR_CRONENABLE:
            cronStateValue = constants.CRONENABLE_STATE['WORKING']
        else:
            # cronjob state not set
            common.log(constants.LOG_LEVEL_DEBUG, "setCronjobState : controller not enabled: cronjob state not set")
            return False
    elif actionValue == constants.CRONJOB_ACTION['STOP']:
        # check disabling state (only for logging)
        if credmStateValue == constants.CREDMENABLE_STATE['DISABLED'] and cronStateValue == constants.CRONENABLE_STATE['WORKING']:
            common.log(constants.LOG_LEVEL_DEBUG, "setCronjobState :  exist from disabling state")
        cronStateValue = constants.CRONENABLE_STATE['IDLE']
    else:
        common.log(constants.LOG_LEVEL_WARNING, "setCronjobState : invalid command")
        return False

    common.log(constants.LOG_LEVEL_DEBUG, f"setCronjobState : cronjob set to {cronStateValue}")
    return setControllerState(cronState=cronStateValue)


###########################################
# checkControllerState
#
# initialize values of CONTROLLER_STATE_SECRET_NAME
#
# in:
# out:  boolean
###########################################
def checkControllerState():
    common.log(constants.LOG_LEVEL_INFO, "checkControllerState : check initial values")
    # check if values in secret are different from default
    credmStateValue, cronStateValue, enableStateValue = getMonitoringState(allFlag=True)
    if not credmStateValue == constants.CREDMENABLE_STATE['ENABLED'] or \
        not cronStateValue == constants.CRONENABLE_STATE['IDLE']:
        common.log(constants.LOG_LEVEL_WARNING, "checkControllerState : found credm controller states NOT default")
        return False
    else:
        return True


###########################################
# __setControllerState
#
# INTERNAL ONLY
#
# descr: set values to ENABLE_STATE_SECRET
#
# in: credmState, cronState
# out:  true/false
###########################################
def setControllerState(credmState=None, cronState=None):

    common.log(constants.LOG_LEVEL_DEBUG, f"setControllerState : credm: {credmState} cron: {cronState}")
    # read secret
    secret_data = k8sApiInterface.readSecretData(constants.CONTROLLER_STATE_SECRET_NAME, constants.NAMESPACE)
    # encode and patch values
    if credmState is not None:
        credmEnableStateValueEnc = common.encodeString(credmState)
        secret_data.data[constants.CONTROLLER_STATE_SECRET_CREDMSTATE_FIELD] = credmEnableStateValueEnc
    if cronState is not None:
        cronWorkingStateValueEnc = common.encodeString(cronState)
        secret_data.data[constants.CONTROLLER_STATE_SECRET_CRONSTATE_FIELD] = cronWorkingStateValueEnc
    # update secret
    res = k8sApiInterface.updateSecretData(constants.CONTROLLER_STATE_SECRET_NAME, constants.NAMESPACE, secret_data)
    common.log(constants.LOG_LEVEL_DEBUG, f"setControllerState : result : {res}")
    return res


###########################################
###########################################
#
#   THREAD TRANSITION ENABLING TO ENABLED
#
###########################################
###########################################



###########################################
# goEnabled
#
# descr: create and run a thread to execute all steps
#        for transition from enabling to enabled
#
# in: none
# out:  boolean
###########################################
def goEnabled():

    common.log(constants.LOG_LEVEL_INFO, "goEnabled: STARTING ...")
    result = True

    # execute thread
    #goEnabled_thread = threading.Thread(target = credmControllerTransitionFromEnablingToEnabled)
    #goEnabled_thread.start()
    #common.log(constants.LOG_LEVEL_DEBUG, "goEnabled: thread is starting running to execute all steps to go in Enabled state")
    #if result == True:
    #    common.log(constants.LOG_LEVEL_DEBUG, "goEnabled: ... END with SUCCESS")
    #else:
    #    common.log(constants.LOG_LEVEL_WARNING, "goEnabled: ... END with FAILURE")

    # execute script to start external job
    cmd = "/credm/scripts/startms8ms9job.sh"
    common.log(constants.LOG_LEVEL_DEBUG, "goEnabled; start external job script:"+cmd)
    result = common.executeCommand(cmd, constants.LOG_FILENAME)

    return result

