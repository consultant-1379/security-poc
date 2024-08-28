#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  COMMON FUNCTION (generic)    #
#                               #
#################################

import os
import sys
import stat
import shutil
import datetime
import base64
import re
import constants
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import time


#
# utility functions
#


###########################################
# date of the day
###########################################
def today():
  return datetime.date.today().strftime('%d-%b-%Y')

###########################################
# time 
###########################################
def timeNow():
  return datetime.datetime.now().strftime("%m/%d/%Y-%H:%M:%S")


###########################################
# log
###########################################
def log(level="DEBUG", *arguments):
    if level == constants.LOG_LEVEL_ERROR:
        logging.error(*arguments)
    if level == constants.LOG_LEVEL_WARNING:
        logging.warning(*arguments)
    if level == constants.LOG_LEVEL_DEBUG:
        logging.debug(*arguments)
    if level == constants.LOG_LEVEL_INFO:
        logging.info(*arguments)    
    #print("%s : %s : %s" % (datetime.datetime.now(), level, message))

 
###########################################
# log config
###########################################
def logConfig():

    # log on stdout
    logging.basicConfig(format='%(asctime)s-[%(levelname)s]---%(message)s', level=logging.DEBUG)

    logger = logging.getLogger()
    logger.propagate = False

    # log on file with logrotate
    logHandler = logging.handlers.RotatingFileHandler(constants.LOG_FILENAME, \
        maxBytes=constants.LOG_ROTATE_SIZE, backupCount=constants.LOG_ROTATE_NUM)
    formatter = logging.Formatter('%(asctime)s-[%(levelname)s]-%(message)s')
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)

    # log directly to rsyslog (NOT WORKING)
    # https://docs.python.org/3.6/library/logging.handlers.html  # sysloghandler
    #sys_log_handler = logging.handlers.SysLogHandler(address='/var/log/syslog')
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #sys_log_handler.setFormatter(formatter)
    #logging.getLogger().addHandler(sys_log_handler)


###########################################
# stringSanitize
#    check if string
#    check max len
#    check bleach.clean
# in: string
# out:  boolean
###########################################
def stringSanitize(message, validSet=[]):

    if not type(message) == str:
        log(constants.LOG_LEVEL_WARNING, "stringSanitize: NOT STRING")
        return False

    if len(validSet) >= 1:
        # check if message is in valid set of strings
        if not message in validSet:
            log(constants.LOG_LEVEL_WARNING, "stringSanitize: NOT VALID SET")
            return False

    MAX_STRING_LEN = 62
    if len(message) > MAX_STRING_LEN:
        log(constants.LOG_LEVEL_WARNING, "stringSanitize: TOO LONG")
        return False

    regexp = re.compile('[^\-_0-9a-zA-Z]')
    if regexp.search(message):
        log(constants.LOG_LEVEL_WARNING, "stringSanitize: EVIL CHARACTERS")
        return False

    log(constants.LOG_LEVEL_DEBUG, f"stringSanitize {message} passed")
    return True


###########################################
# replace_all_IGNORECASE
# in: patter, repl, string
# out:  string with all patterm replaced by repl
###########################################
def replaceAllIgnorecase(pattern, repl, string) -> str:
    occurrences = re.findall(pattern, string, re.IGNORECASE)
    for occurrence in occurrences:
        string = string.replace(occurrence, repl)
        return string


###########################################
# encodeString
# in: clear string
# out: base64 string
###########################################
def encodeString(message):
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes).decode('ascii')
    if constants.LOG_FILE_DEBUG_FLAG:
        print("encodeString: message %s  -> encode64 %s" % (message, base64_bytes), flush=True)
    return base64_bytes


###########################################
# decodeString
# in: base64 string
# out: clear string
###########################################
def decodeString(message64):
    base64_bytes = message64.encode('ascii')
    message = base64.b64decode(base64_bytes).decode('ascii')
    if constants.LOG_FILE_DEBUG_FLAG:
        print("decodeString: encode64 %s -> decoded %s" % (message64, message), flush=True)
    return message


###########################################
# decodeBinary
# in: base64 string
# out: clear string
###########################################
def decodeBinary(message64):
    base64_bytes = message64.encode('ascii')
    message = base64.b64decode(base64_bytes)
    if constants.LOG_FILE_DEBUG_FLAG:
        print("decodeBinary:  binary encode64 %s -> decoded %s" % (message64, message), flush=True)
    return message


###########################################
# readTextFile
# in: filename string
# out: clear string
###########################################
def readTextFile(filename):
    if constants.LOG_FILE_DEBUG_FLAG:
        print("readTextFile: {}".format(filename), flush=True)   
    with open(filename, "r") as file:
       fileText = file.read()
    return fileText


###########################################
# readFileToBase64
# in: filename string
# out: clear string
###########################################
def readFileToBase64(filename):
    file_text: str = ""
    with open(filename, "rb") as f:
        encoded_file = base64.b64encode(f.read())
        file_text = encoded_file.decode('utf-8')
    if constants.LOG_FILE_DEBUG_FLAG:
        print("----- readFileToBase64 %s" % filename)
        print(file_text)
        print("------", flush=True)
    return file_text


###########################################
# writeBinaryFile
# in: filename string
# in: storage binary data
###########################################
def writeBinaryFile(filename, storage):
    createFileFolder(filename)
    if constants.LOG_FILE_DEBUG_FLAG:
        print("----- writeBinaryFile %s" % filename)
        print(storage)
        print("------", flush=True)
    binary = base64.b64decode(storage)
    # print(binary)
    with open(filename, "wb") as file:
        file.write(binary)


###########################################
# writeTextFile
# in: filename
# in: clear string
###########################################
def writeTextFile(filename, text):
    if constants.LOG_FILE_DEBUG_FLAG:
        print("writeTextFile: {}".format(filename), flush=True) 
    createFileFolder(filename)
    with open(filename, "w") as file:
        file.write(text)


###########################################
# appendTextFile
# in: filename
# in: clear string
###########################################
def appendTextFile(filename, text):
    if constants.LOG_FILE_DEBUG_FLAG:
        print("appendTextFile: {}".format(filename), flush=True) 
    createFileFolder(filename)
    with open(filename, "a") as file:
        file.write(text+ '\n')


###########################################
# createFolder
# in: folderName string 
###########################################
def createFolder(folderName):
    # build dir
    if not os.path.exists(folderName):
        if constants.LOG_FILE_DEBUG_FLAG:
            print("createFolder: {}".format(folderName), flush=True)
        os.makedirs(folderName)
    # check result of operation (os.makedirs does not return value)
    if not os.path.exists(folderName):
        log(constants.LOG_LEVEL_WARNING, f"createFolder: directory NOT created {folderName}")


###########################################
# createFileFolder
# in: fullFileName string 
###########################################
def createFileFolder(fullFileName):
    folder_name = os.path.dirname(fullFileName)
    # build dir
    createFolder(folder_name)


###########################################
# removePath
# in: path string 
###########################################
def removePath(path):

    #log(constants.LOG_LEVEL_WARNING, f"removePath: path {path}")

    if constants.LOG_FILE_DEBUG_FLAG:
        print("removePath : {}".format(path), flush=True)
    """ param <path> could either be relative or absolute. """
    if os.path.isfile(path) or os.path.islink(path):
        os.remove(path)  # remove the file
    elif os.path.isdir(path):
        shutil.rmtree(path)  # remove dir and all contains
    else:
        if constants.LOG_FILE_DEBUG_FLAG:
            print("removePath: file {} is not a file or dir.".format(path), flush=True)


###########################################
# findCredmControllerApiVersion
# in: none
# out: apiversion string
###########################################
def findCredmControllerApiVersion():
    text = readTextFile(constants.CREDM_CONTROLLER_API_VERSION_FILE)
    # print(text)
    string_list = []
    string_list = text.split("=")
    if constants.LOG_DEBUG_FLAG:
        print("findCredmControllerApiVersion = " + string_list, flush=True)
    return string_list[1]


###########################################
# writeSPShostFiles
# in: spsHostsList tuple (filename, ip, apiversion)
###########################################
def writeSPShostFiles(spsHostsList):
    # for each item write the host file
    for item in spsHostsList:
        sps_file_name = item[0]
        sps_ip = item[1]
        sps_api_version = item[2]
        log(constants.LOG_LEVEL_DEBUG, f"writeSPShostFiles: SPS hostfile: {sps_file_name} {sps_ip} {sps_api_version}")
        full_filename = constants.SPS_FILES_FOLDER + sps_file_name
        text = "ipv4=" + sps_ip + "\n" + "version=" + sps_api_version + "\n"
        writeTextFile(full_filename, text)


###########################################
# calculateStringMD5
# find MD5 hash value of a string
# in: string
# out: MD5 hash 
###########################################
def calculateStringMD5(text):
    md5 = hashlib.md5(text.encode('utf-8')).hexdigest()

    #if constants.LOG_DEBUG_FLAG:        
    #    print("calculateStringMD5 : md5 hash for text %s = %s" % (text, md5))

    return md5


###########################################
# calculateFileMD5
# find MD5 hash value of a file
# in: filename, i.e. the full path for filename
# out: MD5 hash 
###########################################
def calculateFileMD5(filename):
    md5_hash = hashlib.md5()
    with open(filename,"rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            md5_hash.update(byte_block)
        md5 = md5_hash.hexdigest()
            
    if constants.LOG_DEBUG_FLAG:        
        print("calculateFileMD5 : md5 hash for filename %s = %s" % (filename, md5), flush=True)
        
    return md5


###########################################
# doesFileExist
# in: fullFileName string 
# out: True or False
###########################################
def doesFileExist(fullFileName):    
    if os.path.isfile(fullFileName) and os.access(fullFileName, os.R_OK):
        return True
    else:
        return False


###########################################
# setExecutableOnFile
# in: fullFileName string 
# out: True or False
###########################################
def setExecutableOnFile(fullFileName): 
    os.chmod(fullFileName, stat.S_IEXEC)  
    # Check for execution access 
    if os.path.isfile(fullFileName) and os.access(fullFileName, os.X_OK):
        return True
    else:
        log(constants.LOG_LEVEL_WARNING, f"setExecutableOnFile: failed on {fullFileName}")
        return False


###########################################
# executeCommand
# in: command string 
# in: logfile (optional)
# out: True or False
###########################################
def executeCommand(command, logfile = ""):     
    cmd = command
    if (logfile != ""):
        cmd = cmd + " &>> " + logfile      
    log(constants.LOG_LEVEL_DEBUG, f"executeCommand: cmd = {cmd}") 
    ret = os.system(cmd)
    if constants.LOG_DEBUG_FLAG and doesFileExist(logfile):
        print(readTextFile(logfile), flush=True)
    return ret


###########################################
# executeScriptsOnFolder
# in: folderName string
# in: logfile (optional) 
# out: True or False
###########################################
def executeScriptsOnFolder(folder, logfile = ""): 
    log(constants.LOG_LEVEL_DEBUG, f"executeScriptsOnFolder: folder = {folder}")    
    arr = os.listdir(folder)
    log(constants.LOG_LEVEL_DEBUG, f"executeScriptsOnFolder: items = {len(arr)}")
    for item in arr:
        cmd = folder + item
        if (logfile != ""):
            cmd = cmd + " &>> " + logfile 
        ret = executeCommand(cmd)
        log(constants.LOG_LEVEL_DEBUG, f"executeScriptsOnFolder: result = {ret}") 
        if ret != 0:
            log(constants.LOG_LEVEL_WARNING, f"executeScriptsOnFolder: script error = {ret}") 
            return False
    return True
       

###########################################
# evaluateCertRequestAge
# in: dateInSeconds
# in: timeout
# out: True or False
###########################################
def evaluateCertRequestAge(dateInSeconds, timeout):
    dateInSeconds = int(dateInSeconds)
    timeout = int(timeout)
    nowInSeconds = int(time.time())

    if ( timeout == 0 ):
        log(constants.LOG_LEVEL_DEBUG, f"evaluateCertRequestAge: no timeout given, return ok")
        return True

    #log(constants.LOG_LEVEL_DEBUG, f"evaluateCertRequestAge: sending time = {dateInSeconds}")
    log(constants.LOG_LEVEL_DEBUG, f"evaluateCertRequestAge: sending time = {time.ctime(dateInSeconds)}")
    log(constants.LOG_LEVEL_DEBUG, f"evaluateCertRequestAge: timeout = {timeout}")
    #log(constants.LOG_LEVEL_DEBUG, f"evaluateCertRequestAge: time now = {nowInSeconds}")
    differenceTime = nowInSeconds - dateInSeconds
    log(constants.LOG_LEVEL_DEBUG, f"evaluateCertRequestAge: delayTime = {differenceTime}")
    if ( differenceTime > ( timeout - constants.PROCESSING_TIMEOUT ) ):
        log(constants.LOG_LEVEL_DEBUG, f"evaluateCertRequestAge: too late...certrequest rest to be discarded")
        return False

    return True
