#!/bin/bash

VAULT_PATH=/ericsson/security/data/vault                                        #Path to store vault.keystore file
VAULT_PATH_OLD=/ericsson/pkira/data/vault                                       #Path to old vault file
KEY_TOOL=/usr/java/default/bin/keytool                                          #Keytool Path
VAULT_SCRIPT=/ericsson/3pp/jboss/bin/vault.sh                                   #JBOSS vault Script

VAULT_INFO_FILE=/ericsson/security/data/vault_info_cmp.txt                      #File to store content of vault that need to added in standalone
STANDALONE_PATH=/ericsson/3pp/jboss/standalone/configuration/standalone-enm.xml #Standalone file path

KEY_STORE=vault.keystore               #File name of the vault store
KEY_PWD=6wkv/gSwMTY                    #vault key password
STORE_PWD=6wkv/gSwMTY				   #vault store password
STORE_ALIAS=vault                      #vault store alias name
KEY_SIZE=128                           #Size of the key
KEY_ALGORITHM=AES					   #Key algorithm name
ITERATION_COUNT=8                      #Iteration count to store the password
SALT_PWD=saltpswd                      #Salt password to store the password
STORE_TYPE=jceks					   #Type of the key store


PWD_TO_BE_STORED=D4RvN3Jz              #Actual password to be stored
ATTRIBUTE_NAME=SecuredAttributeName    #Attribute name stored s reference
BLOCK_NAME=CMP_VAULT                   #Block name of the password stored

#Creates a vault keystore to store the passwords to be used in the applications
create_keystore(){
if [ -d $VAULT_PATH_OLD ]; then
       rm -rf $VAULT_PATH_OLD
fi
if [ ! -d $VAULT_PATH ]; then
        mkdir -p $VAULT_PATH
        $KEY_TOOL -genseckey -alias $STORE_ALIAS -storetype $STORE_TYPE -keyalg $KEY_ALGORITHM -validity 10000 -keysize $KEY_SIZE -keypass $KEY_PWD -storepass $STORE_PWD  -keystore $VAULT_PATH/$KEY_STORE -dname "cn=JBOSS_VAULT, ou=ENM, o=Ericsson, c=SE"
else
        echo "Vault path directory already exits"
fi
}

# open vault, give keystore to vault and save password into vault block
save_passwords(){
ATTRIBUTE_LIST=$1
for ATTRIBUTE_NAME in $ATTRIBUTE_LIST; do
JAVA_OPTS="-Djboss.modules.system.pkgs=com.sun.crypto.provider" sh $VAULT_SCRIPT -e $VAULT_PATH/  -k $VAULT_PATH/$KEY_STORE -p $STORE_PWD -s $SALT_PWD -i $ITERATION_COUNT -v $STORE_ALIAS -a $ATTRIBUTE_NAME -b $BLOCK_NAME -x $PWD_TO_BE_STORED > $VAULT_INFO_FILE #Store vault into a temporary file
done
}

update_standalone(){

if grep -Fq "<vault>" $STANDALONE_PATH
then
    echo "Vault configuration already exits in standalone-enm.xml"
else
	sed -i -n '/<vault>/,/<\/vault>/p' $VAULT_INFO_FILE                      # Only vault configuration information is retained in the file
	sed -i 's/<management> ...//;s/^/    /;1i\\' $VAULT_INFO_FILE            # To format vault info to fit in standalone file
	sed -i "/<\/system-properties>/ r $VAULT_INFO_FILE" $STANDALONE_PATH     # To copy Vault information to stand alone standalone
fi

rm -rf $VAULT_INFO_FILE
}


if grep -Fq "CMP_VAULT" $STANDALONE_PATH
then
    echo "CMP vault related system properties already exits in standalone-enm.xml"
else
	create_keystore
	save_passwords "VENDOR_TRUST_CMP CA_TRUST_CMP RA_KEYSTORE_CMP"
	update_standalone
fi