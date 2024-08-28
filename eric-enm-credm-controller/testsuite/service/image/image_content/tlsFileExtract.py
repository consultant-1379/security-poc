
import sys, json, base64

def writeFile(filename, storage):
    print("write file %s" % filename)
    binary=base64.b64decode(storage)
    print(binary)
    with open(filename, "wb") as file:
       file.write(binary)

#
# MAIN
#
if __name__ == "__main__":
   jsonData=json.load(sys.stdin)
   #print(jsonData)
   jsonLen=len(jsonData)
   for x in range(0, jsonLen):
      print("JSON data n:%d" % x)
      jsonItem=jsonData[x]
      filename=jsonItem["filename"]
      print(filename)
      storage=jsonItem["storage"]
      #print(storage)
      writeFile(filename,storage)



