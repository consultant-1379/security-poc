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
import java.io.IOException;
import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command;
import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.utils.XmlFileFilter;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.SystemManagementException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.SystemManagement;

public class CommandCheck implements Command {

    /**
     * 
     */
    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

    private final Properties prop = PropertiesReader.getConfigProperties();
    private final Properties commandProperties = PropertiesReader.getProperties(this.prop.getProperty("commands"));
    private final static String CREDENTIALMANAGERCLI_PATH = "/opt/ericsson/ERICcredentialmanagercli";
    private final CredMaServiceApiController serviceController;
    private final File appXml;
    private final boolean firstDailyRun;

    /**
     * @param appClientConfig
     */
    public CommandCheck(final File filePath, final boolean firstDailyRun) {
        this.appXml = filePath;
        this.firstDailyRun = firstDailyRun;
        System.out.println(" Instantiated CommandCheck ");
        this.serviceController = new CredMaServiceApiControllerImpl();
    }

    @Override
    public int execute() {
        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_START_COMMAND), this.getType());
        System.out.println(" Execute CommandCheck");
        /** TODO change the test algorithm with the proper processing flow **/
        // /* just 4 test */
        // final long millis = System.currentTimeMillis();
        // final long minute = TimeUnit.MILLISECONDS.toMinutes(millis);
        // if ((minute % 5) == 0) {
        // try {
        // //String pathFile = System.getProperty("user.dir") + File.separator +
        // ".state";
        // final String pathFile = this.CREDENTIALMANAGERCLI_PATH +
        // File.separator + ".state";
        // final File f = new File(pathFile);
        // LOG.info("Creating .state file : " + pathFile);
        // f.createNewFile();
        // } catch (final IOException e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
        //
        // }
        /* end of test */

        //System.out.println(" try to call performCheck ");
        if (this.performCheck() == 0) {
            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_END_COMMAND), this.getType());
            System.out.println(" performCheck executed ");
        } else {
            System.out.println(" performCheck return failure ");
        }
        return 0;

    }

    /**
     * TODO this is the incomplete real execute() method if input param is a dir to scan
     **/
    // public int performCheck(final String xmlFilePath) {
    // final File dir = new File(xmlFilePath);
    // //final boolean isCertValid;
    // final File[] filesList = this.findFiles(dir);
    //
    // for (final File serviceXmlFile : filesList) {
    // final ApplicationCertificateConfigInformation myAppConfig =
    // ApplicationCertificateConfigFactory.getInstance(serviceXmlFile);
    //
    // }
    // return 0;
    //
    // }

    public int performCheck() {

		final Command commandOwnCert = new CommandOwnCert(false, true,
				this.serviceController, true, this.firstDailyRun);
		final int res = commandOwnCert.execute();

        if (res != 0) {
            return res;
        }
        final ActionListManager listActionTot = new ActionListManager();

        if (!this.appXml.isDirectory() && this.appXml.isFile()) {
            listActionTot.addListActionsNoDuplicate(this.executeAction(this.appXml));

        } else if (this.appXml.isDirectory()) {
            final File[] filesList = this.findFiles(this.appXml);

			for (final File xmlFile : filesList) {
				listActionTot.addListActionsNoDuplicate(this.executeAction(xmlFile));
			}
		} else {
		        LOG.error("Path " + this.appXml + " doesn't exist");
			throw new CredentialManagerException("Path " + this.appXml
					+ " doesn't exist");
		}
                final Iterator<Actions> actionsIter = listActionTot.getActions().iterator();

		boolean isVMtoRestart = false;
		LOG.info("Looping XML Actions");
		while (actionsIter.hasNext()) {
			final Actions currentActions = actionsIter.next();
			final CredentialManagerActionEnum valueAction = currentActions.getAction();
			LOG.info("Action found: "+valueAction.toString());
			if (valueAction == CredentialManagerActionEnum.VM_RESTART) {
				isVMtoRestart = true;
			} else if (valueAction == CredentialManagerActionEnum.HTTPS_CONNECTOR_RESTART) {
				// TO DO Call HTTPSConnectorRestart with parameters
				this.runHTTPSConnectorRestart(currentActions);
			} else if (valueAction == CredentialManagerActionEnum.RUN_SCRIPT) {
				// TO DO Call Run Script with parameters
				this.runScriptAction(currentActions);
			}
		}
		if (isVMtoRestart) {
			// TO DO Call VM restart script
			this.RestartVM();
		}
		return 0;
	}


    /**
	 * @param currentActions
	 * @throws NumberFormatException
	 */
	private void runHTTPSConnectorRestart(final Actions currentActions)
			throws NumberFormatException {
		final int paramSize = currentActions.getCommand().getParameterName().size();
		LOG.info("Run Connector Restart");
		switch (paramSize) {
		case 1:
			if (currentActions.getCommand().getParameterName().get(0).equals("port")) {
				final int port = Integer.parseInt(currentActions.getCommand()
						.getParameterValue().get(0));
				try {
					SystemManagement.restartHttpConnector(port);
				} catch (final SystemManagementException e) {
				    LOG.error("Restarting Connector on port " + port +" [Failed]");
				    e.printStackTrace();
				}
			}
			break;
		case 2:
		    if (currentActions.getCommand().getParameterName().get(0).equals("port") && currentActions.getCommand().getParameterName().get(1).equals("offset")) {
		        final int port = Integer.parseInt(currentActions.getCommand().getParameterValue().get(0));
		        final int offset = Integer.parseInt(currentActions.getCommand().getParameterValue().get(1));
		        try {
		            SystemManagement.restartHttpConnector(port, offset);
		        } catch (final SystemManagementException e) {
		            LOG.error("Restarting Connector on port " + port +" with offset " + offset + " [Failed]");
		            e.printStackTrace();
		        }
		    }
		    break;
		case 3:
		    if (currentActions.getCommand().getParameterName().get(0).equals("port")
		            && currentActions.getCommand().getParameterName().get(1).equals("host")
		            && currentActions.getCommand().getParameterName().get(2).equals("managementport")) {
		            final int port = Integer.parseInt(currentActions.getCommand().getParameterValue().get(0));
		            final String host = currentActions.getCommand().getParameterValue().get(1);
		            final int managementport = Integer.parseInt(currentActions.getCommand().getParameterValue().get(2));

		            try {
				SystemManagement.restartHttpConnector(port, host,
						managementport);
		            } catch (final SystemManagementException e) {
			        LOG.error("Restarting Connector on port " + port +" on host " + host + " and management port " + managementport + " [Failed]");
				e.printStackTrace();
		            }
		    }
		    break;
		    }
	}

	
    /**
     * @param currentActions
     */
    // TO DO Change visibility to private !!!
    public void runScriptAction(final Actions currentActions) {
        final List<String> cmd = new ArrayList<String>();
        cmd.add(currentActions.getCommand().getPathname().get(0));
        final Iterator<String> parameterIter = currentActions.getCommand().getParameterValue().iterator();
        while (parameterIter.hasNext()) {
            final String currentParameter = parameterIter.next();
            // String parameterName = currentParameter.getName();
            cmd.add(currentParameter);
        }
        this.RunScript(cmd);
    }

	private int RestartVM() {
            LOG.info("Restart VM");

	    final String pathFile = CommandCheck.CREDENTIALMANAGERCLI_PATH
                    + File.separator + ".state";
		try {
			// String pathFile = System.getProperty("user.dir") + File.separator
			// + ".state";
			final File f = new File(pathFile);
			LOG.info("Creating .state file : " + pathFile);
			f.createNewFile();
		} catch (final IOException e) {
		        LOG.error("Creating .state file : " + pathFile + " [Failed]");
			e.printStackTrace();
		}
		return 0;
	}


	private int RunScript(final List<String> cmd) {
		try {
			LOG.info("Run Script XML Action " + cmd.toString());
			final ProcessBuilder pb = new ProcessBuilder(cmd).inheritIO();
			final Process p = pb.start();
			p.waitFor();
		} catch (final Exception e) {
		    LOG.error("Run Script XML Action " + cmd.toString() + " [Failed]");
		    e.printStackTrace();
		}
        return 0;
    }

    /**
     * 
     */
    private List<Actions> executeAction(final File xmlFile) {
        
        System.out.println("...CHECK ... parsing "+xmlFile.getName());
        
        try {
            final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(xmlFile);
            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_START_COMMAND), this.getType());
            final List<Actions> ListActionToDo = this.serviceController.checkActionToPerform(appClientConfig,this.firstDailyRun);
            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_END_COMMAND), this.getType());
            return ListActionToDo;
        } catch (final Exception e) {
            throw new CredentialManagerException(e);
        }
    }

    public File[] findFiles(final File dir) {
        return dir.listFiles(new XmlFileFilter() {

            @Override
            public boolean acceptXml(final File f) {
                return f.isFile();
            }
        });
    }

    @Override
    public COMMAND_TYPE getType() {
        return COMMAND_TYPE.CHECK;
    }

    @Override
    public List<String> getValidArguments() {
        final List<String> list = new ArrayList<String>();
        for (final String vArg : this.commandProperties.getProperty("command.check.valideArguments").split(",")) {
            list.add(vArg);
        }
        return list;
    }

}
