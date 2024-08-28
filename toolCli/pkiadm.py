#!/usr/bin/python

import requests
import json
import urllib3
import sys
import os


def check_file_existence(filename):
    if not os.path.exists(filename):
        print("ERROR {} not accessible".format(filename))
        exit()


command="pkiadm "
importfilename=""
for i, arg in enumerate(sys.argv):
    if (i != 0):
        command += arg
        if (i < len(sys.argv) - 1):
            command += " "
        if (arg.startswith("file:")):
            importfilename=arg.split(":")[1].replace("\"","")
            

url = 'http://localhost:11111/script-engine/services/command'

if importfilename != "":
    check_file_existence(importfilename)
    filebasename = os.path.basename(importfilename)
    files={'command': (None, command), 'fileName': (None, filebasename), 'file:': (filebasename, open(importfilename, 'rb'))}
else:
    files={'command': (None, command)}

r = requests.post(url, files=files)

try:
    data = json.loads(r.content)

    table = ''''''
    for row in data :
        if "command" in row['dtoType']:
            print("\nCOMMAND: {}\n".format(row['value']))
        if "line" in row['dtoType']:
            print(row['value'])
        if "command" not in row['dtoType'] and "line" not in row['dtoType'] :
            table = ''''''
            for ele in row['elements']:
                i = ele['width'] - len(ele['value'])
                table += '{}{}\t'.format(ele['value'], " "*i)
            print(table)
except ValueError:
    #print(type(r.content))
    #print(r.content.decode())
    print(r.content)


