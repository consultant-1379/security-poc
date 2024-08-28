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
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
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
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * Handler implementation for CertificateManagementEntityExportCertHandler. This provides service to Export Certificate Chain of End-Entity and also single End-Entity certificate as an option.
 *
 * "pkiadm" ( "certmgmt" | "ctm" ) "EECert" EXPORT_CERT EE_ENTITY_NAME CERT_FORMAT [ PASSWORD ] [ NO_CERTIFICATE_CHAIN ]
 *
 * EXPORT_CERT ::= ( "--exportcert" | "-expcert" )
 *
 * EE_ENTITY_NAME ::= ( "--entityname" | "-en" ) " " <entity_name>
 *
 * CERT_FORMAT ::= ( "--format"|"-f" ) " ( "JKS" | "P12" | "PEM" )
 *
 * PASSWORD ::= ( "--password"|"-pass" ) " " <password>
 *
 * NO_CERTIFICATE_CHAIN ::= ( "--nochain" | "-nch" )
 *
 * @author xsrirko
 *
 */
@CommandType(PkiCommandType.ENTITYCERTMANAGEMENTEXPORT)
@Local(CommandHandlerInterface.class)
public class CertificateManagementEntityExportCertHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CertificateUtils certUtil;

    @Inject
    FileUtility fileUtil;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    CliUtil cliUtil;


    @Inject
    SystemRecorder systemRecorder;

    private String entityName = null;

    /**
     * Handles command to Export Certificate Chain or certificate for End Entity
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("ENTITYCERTMANAGEMENTEXPORT command handler");

        PkiCommandResponse commandResponse = null;

        String filePath = null;

        try {

            entityName = command.getValueString(Constants.ENTITYNAME);

            if (ValidationUtils.isNullOrEmpty(entityName)) {

                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            filePath = exportCertificate(command);
            commandResponse = buildCommandResponse(filePath);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_DOES_NOT_EXIST, entityNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_DOES_NOT_EXIST);
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.debug(PkiErrorCodes.NO_CERTIFICATE_FOUND, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND);
        } catch (CertificateServiceException certificateServiceException) {
            logger.debug(PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, noSuchAlgorithmException);
            return prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final IOException iOException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.IO_ERROR + Constants.SPACE_STRING + iOException.getMessage(), iOException);
        } catch (final InvalidCAException invalidCAException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidCAException.getMessage());
        } catch (final InvalidCertificateStatusException invalidCertificateStatusException) {
            logger.debug(invalidCertificateStatusException.getMessage(), invalidCertificateStatusException);
            return prepareErrorMessage(ErrorType.INVALID_CERTIFICATE_STATUS_EXCEPTION.toInt(), invalidCertificateStatusException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityException.getMessage());
        } catch (NoSuchProviderException noSuchProviderException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, noSuchProviderException);
        } catch (KeyStoreException | CertificateException exception) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON + Constants.SPACE_STRING + exception.getMessage(), exception);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error("Error occurred while exporting CA Entity[{}] certificate. Error={} Exception={}", entityName, PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYCERTMANAGEMENTEXPORT", "CertificateManagementEntityExportCertHandler",
                "Exported CertificateChain/Certificate for End Entity: " + entityName + " successfully",
                "Export Certificate Chain or certificate for End Entity", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return commandResponse;
    }


    private String exportCertificate(final PkiPropertyCommand command) throws CertificateException, CertificateNotFoundException, CertificateServiceException, EntityNotFoundException, IOException,
            IllegalArgumentException, InvalidCAException, InvalidCertificateStatusException, InvalidEntityAttributeException, InvalidEntityException, KeyStoreException, NoSuchAlgorithmException,
            NoSuchProviderException {
        final String format = command.getValueString(Constants.FORMAT);

        String password = Constants.EMPTY_STRING;
        if (command.hasProperty(Constants.PASSWORD)) {
            password = command.getValueString(Constants.PASSWORD);
        }

        List<Certificate> certificates = null;
        if (command.hasProperty(Constants.NOCHAIN)) {
            certificates = eServiceRefProxy.getEndEntityCertificateManagementService().listCertificates_v1(entityName, CertificateStatus.ACTIVE);
        } else {
            certificates = generateCertChain().getCertificates();
        }
        if (certificates == null || certificates.isEmpty()) {
            throw new CertificateNotFoundException(PkiErrorCodes.NO_CERTIFICATE_FOUND);
        }
        return certUtil.convertCertificates(certificates, format, entityName, password);
    }

    private CertificateChain generateCertChain() throws CertificateServiceException, InvalidCAException, InvalidCertificateStatusException, InvalidEntityAttributeException, InvalidEntityException {
        return eServiceRefProxy.getEndEntityCertificateManagementService().getCertificateChain(entityName);
    }

    private PkiCommandResponse buildCommandResponse(final String filePath) {

        PkiCommandResponse pkiCommandResponse = null;
        pkiCommandResponse = buildPkiCommandResponse(pkiWebCliResourceLocalService.getBytesAndDelete(filePath), fileUtil.getFileNameFromAbsolutePath(filePath));
        return pkiCommandResponse;
    }

    private PkiCommandResponse buildPkiCommandResponse(final byte[] fileContents, final String keyStoreFile) {
        final String fileIdentifier = CliUtil.generateKey();
        final DownloadFileHolder downloadFileHolder = generateDownloadFileHolder(keyStoreFile);
        downloadFileHolder.setContentToBeDownloaded(fileContents);
        exportedItemsHolder.save(fileIdentifier, downloadFileHolder);
        logger.info("Downloadable content stored in memory with fileidentifier {}", fileIdentifier);

        final PkiDownloadRequestToScriptEngine commandResponse = new PkiDownloadRequestToScriptEngine();
        commandResponse.setFileIdentifier(fileIdentifier);
        return commandResponse;
    }

    private DownloadFileHolder generateDownloadFileHolder(final String fileName) {

        final DownloadFileHolder downloadFileHolder = new DownloadFileHolder();
        downloadFileHolder.setFileName(fileName);
        downloadFileHolder.setContentType(certUtil.getContentType(fileName));

        return downloadFileHolder;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {}  occured while Exporting the certificate: {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage,cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while Exporting the certificate: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage,Constants.EMPTY_STRING);
    }
}
