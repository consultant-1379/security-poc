/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.ConfigManagementUpdater;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

/**
 * Handler Implementation for disabling the algorithm(s)
 *
 * pkiadm configmgmt|cfg algo (--disable|-d) --name|-n <> --keysize|-ks 1204|1024,2048|512-2048
 *
 * @author xsumnan
 *
 */
@CommandType(PkiCommandType.CONFIGMGMTDISABLE)
@Local(CommandHandlerInterface.class)
public class ConfigManagementDisableHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    private Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    ConfigManagementUpdater configManagementUpdater;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of ConfigManagementDisableHandler for processing the command for disabling of algorithm(s)
     *
     * @param command
     *
     * @return configManagementUpdater
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        List<Algorithm> algorithms = null;

        try {
            algorithms = configManagementUpdater.extractAlgorithmList(command);
            systemRecorder.recordSecurityEvent("PKIWebCLI.CONFIGMGMTDISABLE", "ConfigManagementDisableHandler", "Algorithms disabled successfully : "
                    + algorithms.toString(), "Disable algorithms", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final PKIConfigurationException pkiConfigurationException) {
            return prepareErrorMessage(ErrorType.PKICONFIG_ERROR.toInt(),
                    PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + " Exception occured while updating the algorithm Status " + pkiConfigurationException.getMessage(), pkiConfigurationException);
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(),
                    PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + " Exception occured while updating the algorithm Status " + illegalArgumentException.getMessage(), illegalArgumentException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + " Exception occured while updating the algorithm Status " + exception.getMessage(),
                    exception);
        }

        return configManagementUpdater.update(algorithms, Constants.DISABLE);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while disabling the algorithms {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

}
