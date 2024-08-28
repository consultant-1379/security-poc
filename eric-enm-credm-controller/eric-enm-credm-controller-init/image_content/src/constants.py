#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

###########################################
#                                         #
#  CREDM CONSTANTS - WAIT CONTAINER       #
#                                         #
###########################################

# constant.py

#!/usr/bin/python

from os import environ as env

LOG_DEBUG_FLAG = True

NAMESPACE = str(env.get("NAMESPACE", "default"))

SPS_APP_LABEL = "sps"
POD_LABEL_CREDM_API_VERSION='credm.api.version'

SLEEP_TIME=5

# no more used
CLI_API_VERSION_FILE="/opt/ericsson/ERICcredentialmanagercli/conf/version.properties"
