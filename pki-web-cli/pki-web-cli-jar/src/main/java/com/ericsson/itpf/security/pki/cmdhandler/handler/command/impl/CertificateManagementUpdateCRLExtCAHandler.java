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

import java.security.cert.CRLException;
import java.security.cert.X509CRL;

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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.UpdateCRLParamsValidator;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.UseValidator;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

/**
 * Handler implementation for CertificateManagementUpdateExtCA. This provides service to List certificate(s) for CA entity based on status
 *
 * "pkiadm" "extcaupdatecrl" ( CRL_URL | CRL_FILE ) EXT_CA_NAME CRL_URL ::= "-url" <url> CRL_FILE ::= ( "-fn" | "--filename" ) " file:" <file-name> EXT_CA_NAME ::= ( "-n" | "--name" ) " "
 * <ca-name-value>
 *
 *
 */

@CommandType(PkiCommandType.EXTERNALCAUPDATECRL)
@UseValidator({ UpdateCRLParamsValidator.class })
@Local(CommandHandlerInterface.class)
public class CertificateManagementUpdateCRLExtCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of CertificateManagementUpdateCRLExtCAHandler. Handles command to update CRL for External CA using CRL URL or File
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("EXTERNALCAUPDATECRL command handler");

        final String caName = command.getValueString(Constants.NAME);
        X509CRL x509CRL = null;
        final boolean isCrlFileDefined = command.hasProperty(Constants.CERT_FILE);
        final boolean isCrlRrlDefined = command.hasProperty(Constants.URL);
        String crlURL = null;
        try {
            if (isCrlFileDefined) {
                x509CRL = commandHandlerUtils.getCRLFromInputFile(command);
            } else if (isCrlRrlDefined) {
                x509CRL = commandHandlerUtils.getCRLFromURL(command);
                crlURL = (String) command.getProperties().get("url");
            }
            if (x509CRL == null) {
                return prepareErrorMessage(ErrorType.INVALID_FILE_CONTENT.toInt(), "Error to read CRL file", "Error to read CRL file");
            }
            final ExternalCRLInfo crl = new ExternalCRLInfo();
            X509CRLHolder x509CRLHolder;
            x509CRLHolder = new X509CRLHolder(x509CRL);

            crl.setX509CRL(x509CRLHolder);
            crl.setUpdateURL(crlURL);
            eServiceRefProxy.getExtCaCrlManager().addExternalCRLInfo(caName, crl);

            final StringBuilder strb = new StringBuilder("Added CRL to ");
            strb.append(caName);
            strb.append(" Vendor Credentials. CRL Subject : ");
            strb.append(x509CRL.getIssuerDN().getName());
            systemRecorder.recordSecurityEvent("Pki Security Service", strb.toString(), "anonymous", "CommandType: " + command.getCommandType(), ErrorSeverity.INFORMATIONAL, "IN-PROGRESS");
        } catch (final MissingMandatoryFieldException e) {
            logger.error(PkiErrorCodes.MISSING_MANDATORY_FIELD, e.getMessage());
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, e);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + " " + e.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final ExternalCRLException | CRLException e) {
            logger.error(PkiErrorCodes.NETWORK_PROBLEM_FOR_EXTERNAL_CRL, e.getMessage());
            logger.debug(PkiErrorCodes.NETWORK_PROBLEM_FOR_EXTERNAL_CRL, e);
            return prepareErrorMessage(ErrorType.NETWORK_PROBLEM_FOR_EXTERNAL_CRL.toInt(), PkiErrorCodes.NETWORK_PROBLEM_FOR_EXTERNAL_CRL, PkiErrorCodes.SUGGEST_CHECK_URL);
        } catch (final ExternalCANotFoundException e) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, e.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, e);
            return prepareErrorMessage(ErrorType.EXTCANOTFOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + e.getMessage(), PkiErrorCodes.SUGGEST_CHECK_CANAME_FOR_UPDATECRL);
        } catch (final ExternalCredentialMgmtServiceException e) {
            logger.error(PkiErrorCodes.SERVICE_ERROR, e.getMessage());
            logger.debug(PkiErrorCodes.SERVICE_ERROR, e);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, e);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException.getMessage());
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), "");
        }
        systemRecorder.recordEvent("PKISERVICE.EXTERNALCASERVICE", EventLevel.COARSE, "PKI.EXTERNALCAUPDATECRL", "External CA for which CRL is updated" + caName,
                "CRL for External CA updated successfully");

      return PkiCommandResponse.message(Constants.UPDATE_EXT_CERT_SUCCESSFUL_INFO);

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String suggetsedSolution) {
        logger.error("Error occured while adding the crl: {}" ,errorString);
        return PkiCommandResponse.message(errorCode, errorString, suggetsedSolution);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error:{} occured while listing the certificates:{}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured when reissuing the CA certificate {] " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(CliUtil.buildMessage(errorCode, errorMessage));
    }

}