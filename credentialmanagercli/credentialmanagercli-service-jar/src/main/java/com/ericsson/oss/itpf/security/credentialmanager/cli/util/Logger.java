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
package com.ericsson.oss.itpf.security.credentialmanager.cli.util;

import java.util.Properties;

// TORF-562254 update log4j
import org.apache.logging.log4j.LogManager;

public class Logger implements LoggerPropertiesConstants {

    private static final Properties configProperties = PropertiesReader.getConfigProperties();
    private static Properties logMessagesProperties;
    private static Properties logErrorMessagesProperties;
    private static org.apache.logging.log4j.Logger cliLogger;

    public static org.apache.logging.log4j.Logger getLogger() {

        try {
            if (cliLogger == null) {
                cliLogger = LogManager.getLogger("CredentialManagerCLI");
                cliLogger.debug("Logger : getLogger");
            }
            return cliLogger;
        } catch (final Exception e) {
            return getDefaultLogger();
        }
    }

    
    public static org.apache.logging.log4j.Logger getDefaultLogger() {
        org.apache.logging.log4j.Logger defLogger;
        defLogger = LogManager.getLogger();
        defLogger.debug("Logger : getDefaultLogger");
        return defLogger;
    }

    public static String getLogMessage(final String msgId) {

        if (logMessagesProperties == null) {
            try {
                logMessagesProperties = PropertiesReader.getProperties(configProperties.getProperty("log_messages"));
            } catch (final Exception e) {
                return "";
            }
        }
        String msg = logMessagesProperties.getProperty(msgId);
        if (msg == null || msg.trim().equals("")) {
            msg = getLogErrorMessage(msgId);
        }

        return msg;
    }

    private static String getLogErrorMessage(final String msgId) {
        if (logErrorMessagesProperties == null) {
            try {
                logErrorMessagesProperties = PropertiesReader.getProperties(configProperties
                        .getProperty("log_error_messages"));
            } catch (final Exception e) {
                return "";
            }

        }
        return logErrorMessagesProperties.getProperty(msgId);
    }

}
