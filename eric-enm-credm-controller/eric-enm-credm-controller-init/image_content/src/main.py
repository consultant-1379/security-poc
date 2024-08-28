#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  MAIN - WAIT CONTAINER        #
#                               #
#################################

#!/usr/bin/python

import time
import common
import constants

def initApp():

    foundSpsWithRightApiVersion = False

    while foundSpsWithRightApiVersion == False:
        cliApiVersion = common.findCredmControllerApiVersion()
        if constants.LOG_DEBUG_FLAG == True:
            print("-------------")
            print("INIT: wait for SPS PODs")
            print("api version from version.properties : " + cliApiVersion)

        if constants.LOG_DEBUG_FLAG == True:    
            print("inside loop: wait \n")        
        time.sleep(constants.SLEEP_TIME)
        
        foundSpsWithRightApiVersion = common.findSpsPodWithRightCredmApiVersion(cliApiVersion)

    if constants.LOG_DEBUG_FLAG == True:
        print("foundSpsWithRightApiVersion = {}".format(foundSpsWithRightApiVersion))
        print("outside loop\n")

    if constants.LOG_DEBUG_FLAG == True:
        print("------------")
        print("End inf INIT")

    return 0

#
# MAIN
#
if __name__ == "__main__":
    initApp()
