#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  XML PARSER                   #
#                               #
#################################

from xml.dom import minidom

import constants
import globalData
import common


#
# parse XML file to extract file and folders
#
def parser(xml_data_string):
    
    common.log(constants.LOG_LEVEL_DEBUG, "parser xml data")

    # parse XML
    xmldoc = minidom.parseString(xml_data_string)
    # print("XMLDOC")
    # print(xmldoc.toxml())

    # keystore locations
    if constants.LOG_DEBUG_FLAG:
        print("KEYSTORE")
    keystore_xm_ldata = xmldoc.getElementsByTagName(constants.XML_KEYSTORE)
    for keystoreXMLitem in keystore_xm_ldata:
        # print("keystoreXMLdata")
        # print(keystoreXMLitem.toxml())
        locationParse(keystoreXMLitem, constants.XML_STORELOCATION, globalData.tlsItemsList, constants.TLSSTORE_TYPE['FILE'])
        locationParse(keystoreXMLitem, constants.XML_KEYFILELOCATION, globalData.tlsItemsList, constants.TLSSTORE_TYPE['FILE'])
        locationParse(keystoreXMLitem, constants.XML_CERTIFICATELOCATION, globalData.tlsItemsList, constants.TLSSTORE_TYPE['FILE'])

    # truststore locations
    if constants.LOG_DEBUG_FLAG:
        print("TRUSTSTORE")
    keystore_xm_ldata = xmldoc.getElementsByTagName(constants.XML_TRUSTSTORE)
    for keystoreXMLitem in keystore_xm_ldata:
        locationParse(keystoreXMLitem, constants.XML_STORELOCATION, globalData.tlsItemsList, constants.TLSSTORE_TYPE['FILE'])
        locationParse(keystoreXMLitem, constants.XML_STOREFOLDER, globalData.tlsItemsList, constants.TLSSTORE_TYPE['FOLDER'])

    # crlstore locations
    if constants.LOG_DEBUG_FLAG:
        print("CRLSTORE")
    crlstore_xm_ldata = xmldoc.getElementsByTagName(constants.XML_CRLSTORE)
    for crlstoreXMLitem in crlstore_xm_ldata:
        locationParse(crlstoreXMLitem, constants.XML_STORELOCATION, globalData.tlsItemsList, constants.TLSSTORE_TYPE['CRLFILE'])
        locationParse(crlstoreXMLitem, constants.XML_STOREFOLDER, globalData.tlsItemsList, constants.TLSSTORE_TYPE['CRLFOLDER'])

    #
    # read postscript
    postscriptList = xmldoc.getElementsByTagName("postscript")
    for item in postscriptList:
        if constants.LOG_DEBUG_FLAG:
            print("POSTSCRIPT:")
        item_list = item.getElementsByTagName('pathname')
        script_cmd_string = item_list[0].childNodes[0].nodeValue
        item_list = item.getElementsByTagName('value')
        for s in item_list:
            script_cmd_string = script_cmd_string + " " + s.childNodes[0].nodeValue
        globalData.tlsItemsList.append(globalData.tlsMetadata(constants.TLSSTORE_TYPE['POSTSCRIPT'], script_cmd_string))


#
# parse Cli XML file to extract file names for certs
#
def parserCli(xml_data_string):
    # parse XML
    xmldoc = minidom.parseString(xml_data_string)

    # keystore location
    if constants.LOG_DEBUG_FLAG:
        print("parserCli : KEYSTORE")
    keystore_xm_ldata = xmldoc.getElementsByTagName(constants.XML_KEYSTORE)
    if len(keystore_xm_ldata) != 1:
        common.log(constants.LOG_LEVEL_WARNING, "parserCli: not correct number of locations (not 1) for keyStore !")
        return False
    for keystoreXMLitem in keystore_xm_ldata:
        globalData.cliKeyStoreLocation = locationParseForCli(keystoreXMLitem, constants.XML_STORELOCATION)
        
    # truststore location
    if constants.LOG_DEBUG_FLAG:
        print("parserCli : TRUSTSTORE")
    truststore_xm_ldata = xmldoc.getElementsByTagName(constants.XML_TRUSTSTORE)
    if len(truststore_xm_ldata) != 1:
        common.log(constants.LOG_LEVEL_WARNING, "parserCli: not correct number of locations (not 1) for TrustStore !")
        return False
    for truststoreXMLitem in truststore_xm_ldata:
        globalData.cliTrustStoreLocation = locationParseForCli(truststoreXMLitem, constants.XML_STORELOCATION)
    
    # no CRLs and Postscripts for cli app
    
    #end function
    return True


#
# look for location items
#
def locationParse(xmldoc, tagName, location_list, itemType):
    if constants.LOG_DEBUG_FLAG:
        print("locationParse: xml tag: %s" % tagName)
    # print(xmldoc.toxml())
    item_list = xmldoc.getElementsByTagName(tagName)
    for item in item_list:
        # print(item.toxml())
        item_value = item.childNodes[0].nodeValue
        if constants.LOG_DEBUG_FLAG:
            print(item_value)
        location_item = globalData.tlsMetadata(itemType, item_value)
        location_item.setCertSecretName("NEW")
        location_list.append(location_item)
        if constants.LOG_DEBUG_FLAG:
            print("locationParse: add globalData " + location_item.readItem())
            

#
# look for location items for cli
#
def locationParseForCli(xmldoc, tagName):
    if constants.LOG_DEBUG_FLAG:
        print("xml tag for cli: %s" % tagName)
    item_list = xmldoc.getElementsByTagName(tagName)
    if len(item_list) != 1:
        print("locationParseForCli: not correct number of locations (not 1) for keyStore or TrustStore !")
    location = item_list[0].childNodes[0].nodeValue
    if constants.LOG_DEBUG_FLAG:
        print("locationParseForCli: location: %s" % location)
    return location
        
    

