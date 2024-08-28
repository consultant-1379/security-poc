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
package com.ericsson.oss.itpf.security.credentialmanager.cli;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.ExecuteCommands;
import com.ericsson.oss.itpf.security.credentialmanager.cli.business.ExecuteCommandsImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;

/**
 *
 * Main class of Credential Manager Application
 *
 */

public class CLI {

    /**
     * Log file
     */
    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

    public static final int SUCCESSFUL = 0;
    public static final int FAILED = 1;
    public static final int HARAKIRI_TIMEOUT = 5000;

    /**
     *
     */
    public CLI(final String[] args) {
        super();
        final ExecuteCommands executeCMD = new ExecuteCommandsImpl();
        executeCMD.execute(args);
    }

    /**
     *
     * @param args
     *            The args are interpreted as commands
     */
    public static void main(final String[] args) {
        int exitValue = 1;

        LOG.debug("CredMa START");

	// TORF-586137 : avoid password on command line
	// values passed as arguments (from credentialmanagerconf.sh)
	// KEYSTOREPASSWORD
	// TRUSTSTOREPASSWORD
        System.setProperty("javax.net.ssl.keyStorePassword", System.getenv("KEYSTOREPASSWORD"));
        System.setProperty("javax.net.ssl.trustStorePassword", System.getenv("TRUSTSTOREPASSWORD"));

        try {
            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_START_APP));
            final ExecuteCommands executeCMD = new ExecuteCommandsImpl();
            exitValue = executeCMD.execute(args);
            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_END_APP));
        } catch (final Exception e) {
            //Logger.getErrorLogger().error("ERROR:", e);
            LOG.error("ERROR:", e);
            try {
                LOG.error(e.getCause().toString());
            } catch (final Exception ex) {
            }
            LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_APP));
            System.out.println("CredMa FAILED");
            System.exit(FAILED);
        }

        // call a thread to kill the process if still running after TIMEOUT
        harakiri(HARAKIRI_TIMEOUT, exitValue);

        if (exitValue == SUCCESSFUL) {
            LOG.info("CredMa OK");
            System.out.println("CredMa OK");

            // force garbage collector to close possibly already opened connections
            Runtime.getRuntime().gc();
            Runtime.getRuntime().runFinalization();

            //LOG.info("CredMa END");
            //System.out.println("CredMa END");

            //            //SOLO PER DEBUG RALLENTO
            //            LOG.info("CredMa END ini delay");
            //            System.out.println("CredMa END ini delay");
            //            try {
            //                Thread.sleep(10000);
            //            } catch (final InterruptedException e) {
            //                // TODO Auto-generated catch block
            //                e.printStackTrace();
            //            }
            //            LOG.info("CredMa END end delay");
            //            System.out.println("CredMa END end delay");
            //            // end debug

            //LOG.info("CredMa SUCCESSFUL");
            //System.out.println("CredMa SUCCESSFULL");

            System.exit(SUCCESSFUL);

        } else {
            LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_APP));
            System.out.println("CredMa FAILED " + exitValue);

            System.exit(FAILED);
        }

    }

    /**
     * thread to kill the entire javaVM if it yet running after the timeout ( remote connections not closed)
     *
     * @param timeout
     * @param exitValue
     * @return
     */
    private static void harakiri(final int timeout, final int exitValue) {

        final Thread t = new Thread() {
            @Override
            public void run() {
                //LOG.info("CredMa harakiri - before timeout");
                //System.out.println("CredMa harakiri - before timeout");
                try {
                    Thread.sleep(timeout);
                } catch (final InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                LOG.info("CredMa harakiri");
                System.out.println("CredMa harakiri");

                // kill
                Runtime.getRuntime().halt(exitValue);
                //LOG.info("CredMa harakiri - after kill");
                //System.out.println("CredMa harakiri - after kill");
            }
        };
        //LOG.info("CredMa harakiri - before thread start");
        //System.out.println("CredMa harakiri - before thread start");
        t.start();
        //LOG.info("CredMa harakiri - after thread start");
        //System.out.println("CredMa harakiri - after thread start");

    }

}
