/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.implementation;

import java.io.File;
import java.util.List;
import java.util.Properties;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.ApplicationCertificateConfigInformation;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiController;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCertificate;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

public class CommandOwnCert implements Command {

    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

    private final Properties configProperties = PropertiesReader.getConfigProperties();
    private final CredMaServiceApiController serviceController;
    private final boolean forceReset;
    private final boolean noLoop;
    private final boolean isCheck;
    private final boolean firstDayRun;

    public CommandOwnCert(final boolean forceResetIn, final boolean noLoop, final CredMaServiceApiController serviceController, final boolean isCheck, final boolean firstDayRun) {
        this.forceReset = forceResetIn;
        this.noLoop = noLoop;
        this.serviceController = serviceController;
        this.isCheck = isCheck;
        this.firstDayRun = firstDayRun;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command#execute()
     */
    @Override
    public int execute() {
        //retrive my own xml cert information file
        final String myXmlFile = this.configProperties.getProperty("credentialmanager.xmlfilename");
        final File myAppXml = new File(myXmlFile);
        final ApplicationCertificateConfigInformation myAppClientConfig = ApplicationCertificateConfigFactory.getInstance(myAppXml);

        // check if my own certificate is present and valid

        final CredentialManagerCertificate confManCert = (myAppClientConfig.getApplicationsInfo().get(0)).getCertificates().get(0);
        final int res = this.serviceController.generateMyOwnCertificate(confManCert, this.forceReset, this.noLoop, this.isCheck, this.firstDayRun);

        if (res != 0) {
            LOG.error("Error generating CredM CLI own certificate");
            return res;
        }
        // install phase
        LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_VALIDATE_COMMANDS));
        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_VALIDATE_END_COMMANDS));

        return res;

    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command#getType()
     */
    @Override
    public COMMAND_TYPE getType() {

        return COMMAND_TYPE.CHECK_CLI_CREDENTIALS;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command#getValidArguments()
     */
    @Override
    public List<String> getValidArguments() {
        // TODO Auto-generated method stub
        return null;
    }

}
