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

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 * Handler implementation for CertMgmtRenewEntityCommonHandler. This provides service to update certificate(s) for end entity based on the type the user provides.
 *
 * "pkiadm"( "certmgmt"| "ctm") "EECert" REISSUE ENTITY_NAME EE_REISSUE_TYPE REISSUE ::("--reissue" |"-ri") ENTITY_NAME ::= ( "--entityname"| "-en") " " <entity_name> EE_REISSUE_TYPE ::= (
 * "–reissuetype "|" -rt") (RENEW FILE_OPTIONS) | (REKEY PASSWORD FORMAT ( "JKS"| "P12" )) RENEW ::= ( "--renew"| "-rn") FILE_OPTIONS ::= CSR_FILE_OPTIONS CSR_FILE_OPTIONS::= ( "--csrfile" | "-csr" )
 * "file:"<input_csr_file> REKEY ::= ( "--rekey" | "-rk") PASSWORD ::= ( "--password"| "-p") " "<password> FORMAT ::= ( "--format"| "-f")
 *
 * @author xpranma
 *
 */

@CommandType(PkiCommandType.ENTITYCERTMANAGEMENTREISSUE)
@Local(CommandHandlerInterface.class)
public class CertMgmtUpdateEntityCommonHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    CertMgmtRenewAndModifyEntityHandler certMgmtRenewAndModifyEntityHandler;

    @Inject
    CertMgmtRekeyEntityHandler certMgmtRekeyEntityHandler;

    @Inject
    SystemRecorder systemRecorder;
    /**
     * Method implementation of CertMgmtRenewEntityCommonHandler. Handles command to update certificate for End Entity based on the update type
     *
     * @param comamnd
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("ENTITYCERTMANAGEMENTRENEW command handler");

        PkiCommandResponse commandResponse = null;

        try {

            final String entityName = command.getValueString(Constants.CERT_GENERATE_ENTITY_NAME);
            if (ValidationUtils.isNullOrEmpty(entityName)) {
                return cliUtil.prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY, null);
            }

            final String reissueType = command.getValueString(Constants.REISSUE_TYPE);
            if (ValidationUtils.isNullOrEmpty(reissueType)) {
                return cliUtil.prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_REISSUE_TYPE, null);
            }

            if (reissueType.equals(Constants.REKEY_OPTION)) {
                commandResponse = certMgmtRekeyEntityHandler.rekeyHandler(command, entityName);
            } else {
                commandResponse = certMgmtRenewAndModifyEntityHandler.renewAndModifyHandler(command, entityName);
            }

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            return prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CertificateGenerationException certificateGenerationException) {
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, certificateGenerationException);
            return prepareErrorMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION + Constants.SPACE_STRING
                    + certificateGenerationException.getMessage());
        } catch (final CertificateServiceException certificateServiceException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(invalidCAException.getMessage(), invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), invalidCAException.getMessage());
        } catch (final InvalidCertificateRequestException invalidCertificateRequestException) {
            return prepareErrorMessage(ErrorType.INVALID_CERTIFICATE_REQUEST_EXCEPTION.toInt(), PkiErrorCodes.INVALID_CERTIFICATE_REQUEST, invalidCertificateRequestException);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND);
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityException.getMessage());
        } catch (final IOException ioException) {
            logger.debug("Error occured while performing rekey or renew and modify of certMgmt entity :" , ioException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE + Constants.SPACE_STRING + ioException.getMessage());
        } catch (final CertificateEncodingException certificateEncodingException) {
            return prepareErrorMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(),
                    PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION + Constants.SPACE_STRING + certificateEncodingException.getMessage(), certificateEncodingException);
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.debug(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION + expiredCertificateException.getMessage());
        } catch (final RevokedCertificateException revokedCertificateException) {
            return prepareErrorMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION, revokedCertificateException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, noSuchAlgorithmException);
            return prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final KeyStoreException | CertificateException exception) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON + Constants.SPACE_STRING + exception.getMessage(), exception);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CERTMGMTUPDATEENTITY", "CertMgmtUpdateEntityCommonHandler",
                "Certificate Updated successfully for end entity: " + command.getValueString(Constants.CERT_GENERATE_ENTITY_NAME),
                "Update certificate for End Entity based on the type the user provides", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return commandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured when reissuing Entity certificate : {}" ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());

    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured when reissuing Entity certificate: {} " , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);

    }

}
