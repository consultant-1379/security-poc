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
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

/**
 * Handler implementation for CertificateManagementRemoveCRLExtCA. This provides service to remove CRLs for CA entity
 *
 * "pkiadm" "extcaremovecrl" ("--name" | "-n") EXT_CA__NAME ("--issuername" | "-in") ISSUER_NAME
 *
 *
 */

@CommandType(PkiCommandType.EXTERNALCAREMOVECRL)
@Local(CommandHandlerInterface.class)
public class CertificateManagementRemoveCRLExtCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    private static final String ERROR_WHILE_DELETION = "Error while deleting entity ";

    @Inject
    Logger logger;

    @Inject
    CliUtil cliutil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("EXTERNALCAREMOVECRL command handler");

        String commandResponseMsg = PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR;
        final String issuerName;
        final String caName;
        try {
            issuerName = command.getValueString(Constants.ISSUER_NAME);
            caName = command.getValueString(Constants.NAME);

            commandResponseMsg = deleteCRLs(caName, issuerName);
        } catch (final MissingMandatoryFieldException ex) {
            logger.error(PkiErrorCodes.MISSING_MANDATORY_FIELD, ex.getMessage());
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, ex);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + " " + ex.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final ExternalCANotFoundException entityNotFoundException) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, entityNotFoundException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, entityNotFoundException);
            return prepareErrorMessage(ErrorType.EXTCANOTFOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + entityNotFoundException.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final CommonRuntimeException commonRuntimeException) {
            logger.error(PkiErrorCodes.RUNTIME_EXCEPTION, commonRuntimeException.getMessage());
            logger.debug(PkiErrorCodes.RUNTIME_EXCEPTION, commonRuntimeException);
            return prepareErrorMessage(ErrorType.COMMON_RUNTIME_ERROR.toInt(), PkiErrorCodes.RUNTIME_EXCEPTION, commonRuntimeException.getMessage());
        } catch (final ExternalCredentialMgmtServiceException internalServiceException) {
            logger.error(PkiErrorCodes.SERVICE_ERROR, internalServiceException.getMessage());
            logger.debug(PkiErrorCodes.SERVICE_ERROR, internalServiceException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), ERROR_WHILE_DELETION, PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY);
        } catch (final ExternalCRLNotFoundException ex) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, ex.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, ex);
            return prepareErrorMessage(ErrorType.CRL_ISSUER_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ARGUMENT + ex.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCA_ISSUERNAME);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException.getMessage());
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliutil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), "");
        }
        systemRecorder.recordEvent("PKISERVICE.EXTERNALCASERVICE", EventLevel.COARSE, "PKI.EXTERNALCAREMOVECRL", "External CA for which crl is removed" + caName,
                "CRL for External CA removed successfully.");
        return PkiCommandResponse.message(commandResponseMsg);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String suggetsedSolution) {
        logger.error("Error occured while deleting the external CA CRLs: {} ", errorString);
        return PkiCommandResponse.message(errorCode, errorString, suggetsedSolution);
    }

    private String deleteCRLs(final String caName, final String issuerName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCRLNotFoundException,
            ExternalCredentialMgmtServiceException {
        String returnMsg = "";

        if (caName == null) {
            returnMsg += "caName is a mandatory Parameter";
            throw new MissingMandatoryFieldException(returnMsg);
        } else {
            eServiceRefProxy.getExtCaCrlManagementService().removeExtCRL(caName, issuerName);
            returnMsg += "CRLs for External CA with name: " + caName + Constants.SUCCESSFULLY_DELETED;
        }

        return returnMsg;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while listing the certificates: {}", PkiWebCliException.ERROR_CODE_START_INT + errorCode, errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }
}
