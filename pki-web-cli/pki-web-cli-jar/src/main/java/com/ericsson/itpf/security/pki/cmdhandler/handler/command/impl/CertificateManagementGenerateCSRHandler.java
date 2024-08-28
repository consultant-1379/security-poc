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

import java.io.IOException;

import javax.ejb.Local;
import javax.inject.Inject;

import org.bouncycastle.util.io.pem.PemObject;
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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.*;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;

/**
 * <p>
 * Handler implementation for CertificateManagementGenerateCSRHandler. This provides service to generate and export CSR for Root CA.
 * </p>
 *
 * "pkiadm"( "certmgmt"| "ctm" ) GENERATE ENTITY_NAME NEW_KEY [FORCE]
 *
 * GENERATE ::= ( "--generatecsr" | "-gc" )
 *
 * ENTITY_NAME ::= ("--caentityname"|"-caen") " " <ca_entity_name>
 *
 * NEW_KEY ::= ("--newkey "|" -nk")("true"|"false")
 *
 * @author xgvgvgv
 */

@CommandType(PkiCommandType.CERTIFICATEMANAGEMENTGENERATECSR)
@Local(CommandHandlerInterface.class)
public class CertificateManagementGenerateCSRHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    private Logger logger;

    @Inject
    CertificateUtils certificateUtils;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CliUtil cliUtil;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    SystemRecorder systemRecorder;

    PkiCommandResponse pkiCommandResponse = null;

    /**
     * Method implementation of CertificateManagementGenerateCSR. Processes the command to generate CSR for Root CA.
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("CERTIFICATEMANAGEMENTGENERATECSR command handler");

        try {
            final String caEntityName = command.getValueString(Constants.CA_ENTITY_NAME);
            final Boolean newKey = Boolean.valueOf(command.getValueString(Constants.NEW_KEY));

            if (ValidationUtils.isNullOrEmpty(caEntityName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            pkiCommandResponse = generateCSR(caEntityName, newKey);
        } catch (final CANotFoundException caNotFoundException) {
            logger.debug(PkiErrorCodes.ROOT_CA_NOT_FOUND_EXCEPTION, caNotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ROOT_CA_NOT_FOUND_EXCEPTION);
        } catch (final CertificateRequestGenerationException certificateRequestGenerationException) {
            logger.debug(PkiErrorCodes.CSR_GENERATION_EXCEPTION, certificateRequestGenerationException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_REQUEST_GENERATION_EXCEPTION.toInt(), PkiErrorCodes.CSR_GENERATION_EXCEPTION + certificateRequestGenerationException.getMessage());
        } catch (final CertificateServiceException certificateServiceException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), PkiErrorCodes.INACTIVE_CA_ENTITY + invalidCAException.getMessage());
        } catch (final InvalidOperationException invalidOperationException) {
            logger.debug(PkiErrorCodes.INVALID_ROOT_CA_ENTITY, invalidOperationException);
            return prepareErrorMessage(ErrorType.INVALID_OPERATION_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ROOT_CA_ENTITY);
        } catch (final IOException ioException) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, ioException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CERTIFICATEMANAGEMENTGENERATECSR", "CertificateManagementGenerateCSRHandler",
                "CSR generated successfully for ROOT CA : " + command.getValueString(Constants.CA_ENTITY_NAME), "Generate CSR for ROOT CA",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return pkiCommandResponse;
    }

    private PkiCommandResponse generateCSR(final String caEntityName, final boolean newKey) throws CANotFoundException, CertificateRequestGenerationException,
            CertificateServiceException, InvalidCAException, InvalidOperationException, IOException {
        String successMsg = null;
        PkiCommandResponse generateCSRPkiCommandResponse = null;
        PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder = eServiceRefProxy.getCsrManagementService().generateCSR(caEntityName, newKey);
        successMsg = String.format(Constants.CSR_SUCCESS_MESSAGE, caEntityName);
        generateCSRPkiCommandResponse = buildCommandResponse(caEntityName, pKCS10CertificationRequestHolder, successMsg);
        return generateCSRPkiCommandResponse;
    }

    private PkiCommandResponse buildCommandResponse(final String caEntityName, final PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder, final String successMsg) throws IOException {
        final String fileName = caEntityName + CliUtil.generateKey() + Constants.CSR_EXTENSION;
        final PemObject pemObject = new PemObject("CERTIFICATE REQUEST", pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded());
        final String pemFilePath = certificateUtils.generatePemFile(pemObject, fileName);

        pkiCommandResponse = cliUtil.buildPkiCommandResponse(fileName, Constants.PEM_CONTENT_TYPE, pkiWebCliResourceLocalService.getBytesAndDelete(pemFilePath), successMsg);
        return pkiCommandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while generating CSR: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while generating CSR: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);

    }
}
