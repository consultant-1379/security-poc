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

import java.security.cert.X509Certificate;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;

/**
 * Handler implementation for CertificateManagementImportHandler.This provide service to import internal Root CA certificate which is signed by
 * external CA and can Re Issue Sub-CA(s) certificate with
 * ReKey/ReNew. Also will do RFC validation of import certificate if user provide true.
 * "pkiadm( "certmgmt" | "ctm" ) IMPORT ENTITY_NAME EXT_CA_CERTIFICATE CA_REISSUE_TYPE RFC_VALIDATION [FORCE]
 * IMPORT ::= ( "--importcert" | "-im" ) ENTITY_NAME ::= ("--caentityname"|"-caen") " " <ca_entity_name> EXT_CA_CERTIFICATE ::= ("--certificate"|"-c")
 * "file:"<input_cert_file> CA_REISSUE_TYPE ::=(
 * "-–careissuetype "|" -crt") (RENEW_SUB_CAS | RENEW_SUB_CAS_WITH_REVOCATION | REKEY_SUB_CAS | REKEY_SUB_CAS_WITH_REVOCATION | NONE) RENEW_SUB_CAS
 * ::= "RENEW_SUB_CAS" RENEW_SUB_CAS_WITH_REVOCATION
 * ::="RENEW_SUB_CAS_WITH_REVOCATION" REKEY_SUB_CAS ::= "REKEY_SUB_CAS" REKEY_SUB_CAS_WITH_REVOCATION ::= "REKEY_SUB_CAS_WITH_REVOCATION"
 * RFC_VALIDATION ::= ("--rfcvalidation"|"-rv")("true"|"false")
 * FORCE::= ("--force"|"-fc")
 *
 * @author xsaufar
 */

@CommandType(PkiCommandType.CERTIFICATEMANAGEMENTIMPORT)
@Local(CommandHandlerInterface.class)
public class CertificateManagementImportHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    CliUtil cliUtil;

    @Inject
    SystemRecorder systemRecorder;
    /**
     * Method implementation of CertificateManagementImportHandler. Processes the command to import internal Root CA certificate.
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("CERTIFICATEMANAGEMENTIMPORT command handler");

        X509Certificate x509Certificate = null;

        try {
            final String caEntityName = command.getValueString(Constants.CA_ENTITY_NAME);
            final boolean rfcValidation = Boolean.parseBoolean(command.getValueString(Constants.RFC_VALIDATION));
            final CAReIssueType caReIssueType = CAReIssueType.valueOf(command.getValueString(Constants.CA_REISSUE_TYPE));

            if (ValidationUtils.isNullOrEmpty(caEntityName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            x509Certificate = commandHandlerUtils.getCertificateFromInputFile(command);

            if (command.hasProperty(Constants.FORCE)) {
                eServiceRefProxy.getCaCertificateManagementService().forceImportCertificate(caEntityName, x509Certificate, rfcValidation,caReIssueType);
            } else {
                eServiceRefProxy.getCaCertificateManagementService().importCertificate(caEntityName, x509Certificate, rfcValidation, caReIssueType);
            }
            systemRecorder.recordSecurityEvent("PKIWebCLI.CERTIFICATEMANAGEMENTIMPORT", "CertificateManagementImportHandler",
                    "Internal Root CA certificate imported successfully for CA : " + command.getValueString(Constants.CA_ENTITY_NAME),
                    "Import Internal Root CA certificate", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            return prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CANotFoundException cANotFoundException) {
            logger.debug(PkiErrorCodes.ROOT_CA_NOT_FOUND_EXCEPTION, cANotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ROOT_CA_NOT_FOUND_EXCEPTION);
        } catch (final CertificateGenerationException certificateGenerationException) {
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_PARSER, certificateGenerationException);
            return prepareErrorMessage(ErrorType.INVALID_FILE_CONTENT.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_PARSER + PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE);
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.debug(PkiErrorCodes.CA_ENTITY_CERTIFICATE_NOT_FOUND, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.INVALID_CERTIFICATE.toInt(), PkiErrorCodes.CA_ENTITY_CERTIFICATE_NOT_FOUND);
        } catch (final RevokedCertificateException revokedCertificateException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION, revokedCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION);
        } catch (final CertificateServiceException certificateServiceException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION + expiredCertificateException.getMessage());
        } catch (final IllegalArgumentException illegalArgumentException) {
            return prepareErrorMessage(ErrorType.INVALID_CERTIFICATE.toInt(), PkiErrorCodes.INVALID_CERTIFICATE + PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE, illegalArgumentException);
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), PkiErrorCodes.INACTIVE_CA_ENTITY + invalidCAException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final InvalidOperationException invalidOperationException) {
            logger.debug(PkiErrorCodes.INVALID_ROOT_CA_ENTITY, invalidOperationException);
            return prepareErrorMessage(ErrorType.INVALID_OPERATION_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ROOT_CA_ENTITY);
        } catch (final IssuerCertificateRevokedException issuerCertificateRevokedException) {
            logger.debug(PkiErrorCodes.ISSUER_CERTIFICATE_REVOKED_EXCEPTION_CA, issuerCertificateRevokedException);
            return prepareErrorMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.ISSUER_CERTIFICATE_REVOKED_EXCEPTION_CA);
        } catch (final CertificateException certificateException) {
            return prepareErrorMessage(ErrorType.EXTCA_CERTIFICATE_FILE_BAD_FORMAT.toInt(), certificateException.getMessage() + PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE, certificateException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage());
        }
        return PkiCommandResponse.message(Constants.CERTIFICATE_IMPORT_SUCCESSFULLY);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while importing the Certificate {}  " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode ,cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while generating entity certificate with csr: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

}
