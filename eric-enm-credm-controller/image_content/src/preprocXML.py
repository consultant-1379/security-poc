#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  PRE-PROC XML                 #
#                               #
#################################

import xml.etree.ElementTree as ET
import common


def preprocxml(servicename, filein, fileout):
    # RULES:
    # TAGS TO CHECK AND REPLACE #
    tag_entityname = "entityname"
    tag_distinguishname = "distinguishname"
    hostname_placeholder = '##HOSTNAME##'
    tag_action = "action"
    toset = 'VMRestart'
    tag_certificate = 'certificate'
    tag_postscript = 'postscript'

    tree = ET.parse(filein)
    root = tree.getroot()
    changes = 0
    for elem in tree.findall('.//' + tag_entityname):
        if elem.text.lower().find(hostname_placeholder.lower()) != -1:
            elem.text = common.replaceAllIgnorecase(hostname_placeholder, servicename, elem.text)
            #elem.text = elem.text.replace(hostname_placeholder, servicename)
            changes += 1

    for elem in tree.findall('.//' + tag_distinguishname):
        if elem.text.lower().find(hostname_placeholder.lower()) != -1:
            elem.text = common.replaceAllIgnorecase(hostname_placeholder, servicename, elem.text)
            changes += 1

    for elem in tree.findall('.//' + tag_action):
        if elem.text != toset:
            elem.text = toset
            changes += 1

    for elem in tree.findall('.//' + tag_certificate):
        post = elem.find(tag_postscript)
        if ET.iselement(post):
            print(post)
            elem.remove(post)
        changes += 1

    tree.write(fileout)

    return changes
