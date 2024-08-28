#!/bin/bash
if [ ! -L /ericsson/tor/data/global.properties ]; then /bin/ln -s /gp/global.properties /ericsson/tor/data/global.properties; fi

/bin/chmod 777 /ericsson/3pp/jboss/bin/post-start/rename_currentxml.sh

