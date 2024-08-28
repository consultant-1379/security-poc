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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * Handler implementation for CertificateManagementExportCACert. This provides service to Export certificate for CA entity.
 *
 * "pkiadm" ( "certmgmt" | "ctm" ) "CACert" EXPORT_CERT CA_ENTITY_NAME CERT_FORMAT [ ] [ CERTIFICATE_CHAIN ]
 *
 * EXPORT_CERT ::= ( "--exportcert" | "-expcert" )
 *
 * CA_ENTITY_NAME ::= ( "--entityname" | "-en" ) " " <entity_name>
 *
 * CERT_FORMAT ::= ( "--format"|"-f" ) " ( "JKS" | "P12" | "PEM" | "DER" )
 *
 * PASSWORD ::= ( "--password"|"-pass" ) " " <password>
 *
 * CERTIFICATE_CHAIN ::= ( "--chain" | "-ch" )
 *
 * @author xsrirko
 *
 */
@CommandType(PkiCommandType.CACERTIFICATEMANAGEMENTEXPORT)
@Local(CommandHandlerInterface.class)
public class CertificateManagementCAExportCertHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CertificateUtils certUtil;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    CliUtil cliUtil;

    @Inject
    FileUtility fileUtil;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    private SystemRecorder systemRecorder;

    private String entityName = null;

    /**
     * Handles command to Export certificate of CAEntity
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("CACERTIFICATEMANAGEMENTEXPORT command handler");

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
        } catch (final CertificateServiceException certificateServiceException) {
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    certificateServiceException);
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, noSuchAlgorithmException);
            return prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final IOException iOException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.IO_ERROR + Constants.SPACE_STRING + iOException.getMessage(), iOException);
        } catch (final NoSuchProviderException noSuchProviderException) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, noSuchProviderException);
        } catch (final KeyStoreException | CertificateException exception) {
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON + Constants.SPACE_STRING + exception.getMessage(), exception);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error("Error occurred while exporting CA Entity[{}] certificate. Error={} Exception={}", entityName, PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.SPACE_STRING + exception.getMessage(), exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.EMPTY_STRING + exception.getMessage());
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CACERTIFICATEMANAGEMENTEXPORT", "CertificateManagementCAExportCertHandler",
                "CA entity certificate exported successfully for entiy : " + entityName,
                "Export certificate for CAEntity", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return commandResponse;
    }

    private String exportCertificate(final PkiPropertyCommand command) throws CertificateException, CertificateNotFoundException, CertificateServiceException, EntityNotFoundException,
            IllegalArgumentException, InvalidEntityAttributeException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final String format = command.getValueString(Constants.FORMAT);

        String password = Constants.EMPTY_STRING;
        if (command.hasProperty(Constants.PASSWORD)) {
            password = command.getValueString(Constants.PASSWORD);
        }

        final List<Certificate> certificates = eServiceRefProxy.getCaCertificateManagementService().listCertificates_v1(entityName, CertificateStatus.ACTIVE);
        if (certificates == null || certificates.isEmpty()) {
            throw new CertificateNotFoundException(PkiErrorCodes.NO_CERTIFICATE_FOUND);
        }
        final String certificateFilePath = certUtil.convertCertificates(certificates, format, entityName, password);
        logger.debug("Certificate file path returned successfully for the entity : {}", entityName);
        return certificateFilePath;
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
        logger.error("Error: {} occured while Exporting the certificate: {} ", PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while Exporting the certificate: {} ", PkiWebCliException.ERROR_CODE_START_INT + errorCode, errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);

    }
}
