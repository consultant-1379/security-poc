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
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CertificateUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ContentType;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;

/**
 * Handler implementation for CertificateManagementGenerateCA. This provides service to generate certificate chain for CA entity
 *
 * "pkiadm" ( "certmgmt" | "ctm" ) "CACert" GENERATE ENTITY_NAME ( FORMAT_OPTIONS | NO_POP_UP ) GENERATE ::= ("--generate" | "-gen") ENTITY_NAME ::= ("--entityname" | "-en") " " <entity_name>
 * FORMAT_OPTIONS ::= FORMAT " " ( ( ( "JKS"| "P12") [ PASSWORD ] ) | ( "PEM" ) ) [ NO_CERTIFICATE_CHAIN ] NO_CERTIFICATE_CHAIN ::= ( "--nochain"| "-nc") NO_POP_UP ::= ( "--nopopup" | "-npop" ) FORMAT
 * ::= ( "--format"| "-f") PASSWORD ::= ( "--password"| "-p") " " <password>
 * 
 * @author xpranma
 *
 */

@CommandType(PkiCommandType.CACERTIFICATEMANAGEMENTGENERATE)
@Local(CommandHandlerInterface.class)
public class CertificateManagementGenerateCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    Logger logger;

    @Inject
    CertificateUtils certutils;

    @Inject
    CliUtil cliUtil;

    @Inject
    FileUtility fileUtil;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    /**
     * Method implementation of CertificateManagementGenerateCA. Handles command to generate certificate for CA Entity
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("CACERTIFICATEMANAGEMENTGENERATE command handler");
        Certificate certificate = null;
        PkiCommandResponse commandResponse = null;
        String filePath = null;
        String password = Constants.EMPTY_STRING;
        List<Certificate> certificates = null;

        try {

            final String entityName = command.getValueString(Constants.CERT_GENERATE_ENTITY_NAME);

            // TODO: Implementing for one entity with reference to TORF-53695. Code has to be implemented for multiple
            // entities.

            if (ValidationUtils.isNullOrEmpty(entityName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            certificate = generateCACertificates(entityName);

            if (command.hasProperty(Constants.FORMAT)) {
                final String format = command.getValueString(Constants.FORMAT);

                if (command.hasProperty(Constants.PASSWORD)) {
                    password = command.getValueString(Constants.PASSWORD);
                }

                if (command.hasProperty(Constants.NOCHAIN)) {
                    certificates = new ArrayList<>();
                    certificates.add(certificate);
                } else {
                    certificates = eServiceRefProxy.getCaCertificateManagementService().getCertificateChain(entityName);
                }
                filePath = certutils.convertCertificates(certificates, format, entityName, password);
                commandResponse = buildCommandResponse(filePath);

            } else if (command.hasProperty(Constants.NOPOPUP)) {
                return new PkiMessageCommandResponse("Certificate Generated Successfully for " + entityName);
            }

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.error(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException.getMessage());
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            return prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CANotFoundException caNotFoundException) {
            logger.error(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, caNotFoundException.getMessage());
            logger.debug(PkiErrorCodes.CA_NOT_FOUND_EXCEPTION, caNotFoundException);
            return prepareErrorMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION);
        } catch (final CertificateGenerationException certificateGenerationException) {
            logger.error(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, certificateGenerationException.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, certificateGenerationException);
            return prepareErrorMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION + Constants.SPACE_STRING
                    + certificateGenerationException.getMessage());
        } catch (final CertificateServiceException certificateServiceException) {
            logger.error(PkiErrorCodes.SERVICE_ERROR, certificateServiceException.getMessage());
            logger.debug(PkiErrorCodes.SERVICE_ERROR, certificateServiceException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.error(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final CommandSyntaxException commandSyntaxException) {
            logger.error(PkiErrorCodes.SYNTAX_ERROR, commandSyntaxException.getMessage());
            logger.debug(PkiErrorCodes.SYNTAX_ERROR, commandSyntaxException);
            return prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), commandSyntaxException.getMessage(), commandSyntaxException);
        } catch (final InvalidCAException invalidCAException) {
            logger.error(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), invalidCAException.getMessage());
        } catch (final IOException iOException) {
            logger.error(PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE, iOException.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE, iOException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE + Constants.SPACE_STRING + iOException.getMessage(), iOException);
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.error(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException.getMessage());
            logger.debug(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION + expiredCertificateException.getMessage());
        } catch (final RevokedCertificateException revokedCertificateException) {
            logger.error(PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION, revokedCertificateException.getMessage());
            logger.debug(PkiErrorCodes.CERTIFICATE_REVOKED_EXCEPTION, revokedCertificateException);
            return prepareErrorMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), revokedCertificateException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException.getMessage());
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final NoSuchProviderException noSuchProviderException) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, noSuchProviderException.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, noSuchProviderException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, noSuchProviderException);
        } catch (final KeyStoreException | CertificateException exception) {
            logger.error(PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON, exception.getMessage());
            logger.debug(PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON, exception);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON + Constants.SPACE_STRING + exception.getMessage(), exception);
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, noSuchAlgorithmException.getMessage());
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, noSuchAlgorithmException);
            return prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordEvent("PKISERVICE.CACERTIFICATEMANAGEMENTSERVICE", EventLevel.COARSE, "PKI.CACERTIFICATEMANAGEMENTGENERATE",
                "CA Entity for which certificate generated: " + command.getValueString(Constants.CERT_GENERATE_ENTITY_NAME), "Certificate generated successfully for CA Entity");
        return commandResponse;
    }

    private Certificate generateCACertificates(final String entityName) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityAttributeException, RevokedCertificateException {

        Certificate certificate = null;

        if (entityName == null) {
            return certificate;
        }

        final String entityNameFilter = entityName.replaceAll(Constants.REPLACE_CHARACTERS, Constants.EMPTY_STRING);

        certificate = eServiceRefProxy.getCaCertificateManagementService().generateCertificate(entityNameFilter.trim());

        return certificate;
    }

    private PkiCommandResponse buildCommandResponse(final String filePath) {

        PkiCommandResponse pkiCommandResponse = null;
        final String fileName = fileUtil.getFileNameFromAbsolutePath(filePath);
        final String contentType = ContentType.valueOf(fileName.substring(fileName.lastIndexOf('.') + 1).toUpperCase()).value();
        pkiCommandResponse = cliUtil.buildPkiCommandResponse(fileName, contentType, pkiWebCliResourceLocalService.getBytesAndDelete(filePath));
        return pkiCommandResponse;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {}  occured while generating the certificate: {} ", PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while generating the certificate: {}", PkiWebCliException.ERROR_CODE_START_INT + errorCode, errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }
}
