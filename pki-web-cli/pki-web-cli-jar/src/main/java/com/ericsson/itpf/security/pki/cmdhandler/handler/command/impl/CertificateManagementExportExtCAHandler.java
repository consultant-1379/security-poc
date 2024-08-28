package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

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

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiDownloadRequestToScriptEngine;
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
import com.ericsson.itpf.security.pki.cmdhandler.util.CertificateUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.DownloadFileHolder;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.ExtcaExportCertificateParamsValidator;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.UseValidator;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

/**
 * Handler implementation for CertificateManagementExportExtCA.
 *
 * "pkiadm" "extcaexport" ("--name" | "-n") EXT_CA_NAME
 *
 *
 */

@CommandType(PkiCommandType.EXTERNALCACERTEXPORT)
@UseValidator({ ExtcaExportCertificateParamsValidator.class })
@Local(CommandHandlerInterface.class)
public class CertificateManagementExportExtCAHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {
    @Inject
    Logger logger;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    @Inject
    CliUtil cliUtil;

    @Inject
    CertificateUtils certUtil;

    @Inject
    FileUtility fileUtil;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation for EXTERNALCACERTEXPORT.Processes the command to export External CA certificate.
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("EXTERNALCACERTEXPORT command handler");
        PkiCommandResponse commandResponse = null;

        final String caName = command.getValueString(Constants.NAME);
        String serialNumber = "";
        if (command.hasProperty(Constants.SERIAL_NUMBER)) {
            serialNumber = command.getValueString(Constants.SERIAL_NUMBER);
        }
        try {
            final List<X509Certificate> certificates = eServiceRefProxy.getExtCaCertificateManagementService().exportCertificate(caName, serialNumber, false);
            String filePath = createPEMCertificate(certificates.get(0), caName);
            commandResponse = buildCommandResponse(filePath);

        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            logger.error(PkiErrorCodes.MISSING_MANDATORY_FIELD, missingMandatoryFieldException.getMessage());
            logger.debug(PkiErrorCodes.MISSING_MANDATORY_FIELD, missingMandatoryFieldException);
            return prepareErrorMessage(ErrorType.MISSING_MANDATORYFIELD_EXCEPTION.toInt(), PkiErrorCodes.MISSING_MANDATORY_FIELD + " " + missingMandatoryFieldException.getMessage(),
                    PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final ExternalCANotFoundException externalCANotFoundException) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, externalCANotFoundException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, externalCANotFoundException);
            return prepareErrorMessage(ErrorType.EXTCANOTFOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + externalCANotFoundException.getMessage(), PkiErrorCodes.SUGGEST_CHECK_EXTCANAME);
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.error(PkiErrorCodes.NO_CERTIFICATE_FOUND, certificateNotFoundException.getMessage());
            logger.debug(PkiErrorCodes.NO_CERTIFICATE_FOUND, certificateNotFoundException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.INVALID_ARGUMENT + " " + PkiErrorCodes.NO_CERTIFICATE_FOUND, PkiErrorCodes.SUGGEST_CHECK_CERTIFICATE_SN);
        } catch (final ExternalCredentialMgmtServiceException externalCredentialMgmtServiceException) {
            logger.error(PkiErrorCodes.SERVICE_ERROR, externalCredentialMgmtServiceException.getMessage());
            logger.debug(PkiErrorCodes.SERVICE_ERROR, externalCredentialMgmtServiceException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY,
                    externalCredentialMgmtServiceException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException.getMessage());
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.SPACE_STRING + exception.getMessage(), "");
        }
        systemRecorder.recordEvent("PKISERVICE.EXTERNALCASERVICE", EventLevel.COARSE, "PKI.EXTERNALCACERTEXPORT ", "Exported certificate for external CA: " + caName,
                "Successfully Exported External CA Certificate.");

        return commandResponse;
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

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String suggetsedSolution) {
        logger.error("Error occured while exporting the certificate: {}", errorString);
        return PkiCommandResponse.message(errorCode, errorString, suggetsedSolution);
    }


    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured while Exporting the certificate: {}  ", PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private static String createPEMCertificate(final X509Certificate certificate, final String caName) throws IOException {
        final Date validity = certificate.getNotAfter();
        final String dateString = validity.toString().replaceAll(" ", "_");
        final String caNameWithoutBlanks = caName.trim().replaceAll(" ", "_");

        String fileName = caNameWithoutBlanks + "_" + dateString;
        final String pemFilePath = CliUtil.getTempFile(fileName, Constants.PEM_EXTENSION);
        Writer writer = null;
        JcaPEMWriter pemWriter = null;
        try {
            writer = new FileWriter(pemFilePath, true);
            pemWriter = new JcaPEMWriter(writer);

            pemWriter.writeObject(certificate);

        } finally {

            if (pemWriter != null) {
                pemWriter.close();
            }
            if (writer != null) {
                writer.close();
            }
        }

        return pemFilePath;
    }

}