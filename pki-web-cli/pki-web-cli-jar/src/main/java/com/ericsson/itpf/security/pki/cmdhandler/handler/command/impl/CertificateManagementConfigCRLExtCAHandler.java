/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.*;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

/**
 * Handler implementation for CertificateManagementConfigCRLExtCA. This provides service to config CRL parameters for a CA entity
 *
 * "pkiadm" "extcaconfigcrl" AUTO_UPDATE EXT_CA_NAME [TIMER] AUTO_UPDATE ::= ( "-au" | "--autoupdate" ) ( "enable" | "disable" ) EXT_CA_NAME ::= ( "-n" | "--name" ) <ca-name-value> TIMER ::= ( "-t" |
 * "--timer" ) <timer-value-days>
 *
 */

@CommandType(PkiCommandType.EXTERNALCACONFIGCRL)
@UseValidator({ ConfigCRLParamsValidator.class, CheckAutoupdateEnableDisableValidator.class })
@Local(CommandHandlerInterface.class)
public class CertificateManagementConfigCRLExtCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    Logger logger;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    CliUtil cliUtil;

    /**
     * Method implementation for EXTERNALCACONFIGCRL.Processes the command to configure CRLs for External CA certificate.
     *
     * @param command
     *
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("EXTERNALCACONFIGCRL command handler");

        final String caName = command.getValueString(Constants.NAME);

        final String crlAutoUpdateEnabled = command.getValueString(Constants.AUTO_UPDATE);
        boolean isCrlAutoUpdateEnabled = true;
        if ("disable".equalsIgnoreCase(crlAutoUpdateEnabled)) {
            isCrlAutoUpdateEnabled = false;
        }
        Integer crlAutoUpdateTimer = Integer.valueOf(0);
        if (command.hasProperty(Constants.TIMER)) {
            final String stringTimer = command.getValueString(Constants.TIMER);
            if (stringTimer != null) {
                crlAutoUpdateTimer = Integer.valueOf(stringTimer);
            }
        }

        try {
            eServiceRefProxy.getExtCaCrlManager().configExternalCRLInfo(caName, isCrlAutoUpdateEnabled, crlAutoUpdateTimer);

        } catch (final MissingMandatoryFieldException e) {
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, e);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + " " + e.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final ExternalCANotFoundException e) {
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, e);
            return prepareErrorMessage(ErrorType.EXTCANOTFOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + e.getMessage(), PkiErrorCodes.SUGGEST_CHECK_CANAME_FOR_UPDATECRL);
        } catch (final ExternalCredentialMgmtServiceException e) {
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, e);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + " " + e.getMessage(), PkiErrorCodes.SUGGEST_CHECK_CANAME_FOR_UPDATECRL);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), "");
        }
        logger.info("CRL parameters configured on external CA: {}", caName);
        systemRecorder.recordSecurityEvent("PKIWebCLI.EXTERNALCACONFIGCRL", "CertificateManagementConfigCRLExtCAHandler",
                "CRL parameters configured on external CA: " + caName + " successfully", "Configure CRLs for External CA certificate",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return PkiCommandResponse.message(Constants.CONFIG_CRL_EXT_CERT_SUCCESSFUL_INFO);

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String suggetsedSolution) {
        logger.error("Error occured while adding the crl: {}" ,errorString);
        return PkiCommandResponse.message(errorCode, errorString, suggetsedSolution);
    }

}