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

import java.io.File;
import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command;
import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.utils.XmlFileFilter;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.ApplicationCertificateConfigInformation;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaServiceApiController;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiControllerImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

public class CommandInstall implements Command {
	/**
     * 
     */
        // TORF-562254 update log4j
	private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();
	// private final ApplicationCertificateConfigInformation appClientConfig;
	private final boolean forceOverWrite = false; // this means delete old requisting
											// certificate files
	//private final boolean forceReset; // this means dlete old own certificate
										// files

	private final Properties configProperties = PropertiesReader
			.getConfigProperties();
	private final Properties commandProperties = PropertiesReader
			.getProperties(this.configProperties.getProperty("commands"));
	private final CredMaServiceApiController serviceController;
	private final File appXml;

	public CommandInstall(final File appXml) {
		this.appXml = appXml;
		//this.forceOverWrite = forceOverWriteIn;
		//this.forceReset = forceResetIn;
		this.serviceController = new CredMaServiceApiControllerImpl();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command#execute
	 * ()
	 */
	@Override
	public int execute() {

		// retrive my own xml cert information file
		final Command commandOwnCert = new CommandOwnCert(false, false,
				this.serviceController, false, false);
		final int res = commandOwnCert.execute();

		if (res != 0) {
			return res;
		}
		// install phase
		LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_VALIDATE_COMMANDS),
				Command.COMMAND_TYPE.INSTALL.toString());
		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_VALIDATE_END_COMMANDS));

		if (this.appXml.isDirectory()) {
	            final File[] filesList = this.findFiles(this.appXml);
	            for (final File xmlFile : filesList) {
	                this.parseXmlAndGenerateKeyAndTrust(xmlFile);
                       }
		} else {	            
		    this.parseXmlAndGenerateKeyAndTrust(this.appXml);
		}
		return 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command#getType
	 * ()
	 */
	@Override
	public COMMAND_TYPE getType() {

		return COMMAND_TYPE.INSTALL;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command#
	 * getValidArguments()
	 */
	@Override
	public List<String> getValidArguments() {
		final List<String> list = new ArrayList<String>();

		for (final String vArg : this.commandProperties.getProperty(
				"command.install.valideArguments").split(",")) {
			list.add(vArg);
		}
		return list;
	}
	
	/**
	 * 
	 * parseXmlAndGenerateKeyAndTrust
	 * 
	 * @param File
	 * @return
	 */

    private int parseXmlAndGenerateKeyAndTrust(final File xmlFile) {

        System.out.println("...INSTALL ... parsing "+xmlFile.getName());
        
        final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(xmlFile);

        try {
            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_START_COMMAND), this.getType());
            this.serviceController.generateKeyAndTrustStore(appClientConfig, this.forceOverWrite);
            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_END_COMMAND), this.getType());
        } catch (final Exception e) {
            throw new CredentialManagerException(e);
        }
        return 0;
    }	
	/**
	 * 
	 * @param dir
	 * @return
	 */
    private File[] findFiles(final File dir) {
        return dir.listFiles(new XmlFileFilter() {

            @Override
            public boolean acceptXml(final File f) {
                return f.isFile();
            }
        });
    }
	    
}
