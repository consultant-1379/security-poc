/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.implementation;

import java.io.PrintWriter;
import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaExternalServiceApiWrapperFactory;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

public class CommandVersion implements Command {

    /**
     * 
     */
    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

    private final Properties prop = PropertiesReader.getProperties(PropertiesReader.getConfigProperties().getProperty(
            "commands"));


    @Override
    public int execute() {
        
        final CredMaExternalServiceApiWrapper extServiceApi = new CredMaExternalServiceApiWrapperFactory()
        .getInstance(PropertiesReader.getConfigProperties().getProperty("servicemanager.implementation"));
        
        //final String apiVersion = PropertiesReader.getConfigProperties().getProperty("credentialserviceapi.version");
        final String interfaceVersion = extServiceApi.getCredentialManagerInterfaceVersion();

        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_START_COMMAND), this.getType());
        LOG.info(interfaceVersion);
        
        final PrintWriter printWriter = new PrintWriter(System.out);
        //printWriter.println("CredentialManagerService api version:"+apiVersion);
        //printWriter.println("CredentialManagerService interface version:"+interfaceVersion);
        printWriter.println(interfaceVersion);
        
        printWriter.flush();
        printWriter.close();
        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_END_COMMAND), this.getType());
        return 0;

    }

    @Override
    public COMMAND_TYPE getType() {
        return COMMAND_TYPE.VERSION;
    }

    @Override
    public List<String> getValidArguments() {
        final List<String> list = new ArrayList<String>();
        for (final String vArg : this.prop.getProperty("command.version.valideArguments").split(",")) {
            list.add(vArg);
        }
        return list;
    }


}
