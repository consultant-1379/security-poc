#!/bin/bash
PASSKEY_PATH="/ericsson/tor/data/idenmgmt"
CERTIFICATE_PATH="/ericsson/tor/data/certificates"
echo "checking passkey path"
if [ ! -d $PASSKEY_PATH ]
then
    echo "creating $PASSKEY_PATH"
    /bin/mkdir $PASSKEY_PATH
fi
echo "checking rootCA path"
if [ ! -d $CERTIFICATE_PATH ]
then
    echo "creating rootCA path"
    /bin/mkdir $CERTIFICATE_PATH
fi
echo "copying passkeys"
/bin/cp -f /var/tmp/*passkey $PASSKEY_PATH
echo "copying rootCA.pem"
/bin/cp -f /var/tmp/rootCA.pem $CERTIFICATE_PATH
