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
import java.security.cert.CertificateEncodingException;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.common.CSRUtil;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.*;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 * Handler implementation for CertMgmtRenewAndModifyEntityHandler. This provides service to renew and modify certificate(s) for end entity based on the type the user provides.
 *
 * @author xpranma
 */
@Local(CommandHandlerInterface.class)
public class CertMgmtRenewAndModifyEntityHandler implements CommandHandlerInterface {

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    protected Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     *
     * @param command
     *            command that contains all the properties which user provides
     * @param entityName
     *            entityName for which certificates shall be updated
     * @return commandResponse
     * @throws AlgorithmNotFoundException
     *             This exception is thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             This exception is thrown to indicate that an exception has occurred during certificate generation
     * @throws CertificateServiceException
     *             This exception is thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             This exception is thrown to indicate to indicate entity is not found
     * @throws InvalidCAException
     *             This exception is thrown when the given CAEntity is not valid.
     * @throws InvalidCertificateRequestException
     *             This exception is thrown to indicate the certificate request is invalid
     * @throws InvalidEntityException
     *             This exception is thrown to indicate invalid entity
     * @throws CertificateEncodingException
     *             This exception is thrown to indicate failure during certificate encoding
     * @throws IOException
     *             This exception is produced by failed or interrupted I/O operations.
     */
    public PkiCommandResponse renewAndModifyHandler(final PkiPropertyCommand command, final String entityName) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException, CertificateEncodingException, IOException {

        logger.info("ENTITYCERTMANAGEMENTRENEW command handler with update type as renew or modification");

        CertificateRequest certificateRequest = null;
        byte[] certificateInBytes = null;

        final String csrData = cliUtil.getFileContentFromCommandProperties(command.getProperties());
        if (ValidationUtils.isNullOrEmpty(csrData)) {
            return cliUtil.prepareErrorMessage(ErrorType.INVALID_CSR_FILE.toInt(), PkiErrorCodes.CSR_FORMAT_ERROR, null);
        }

        certificateRequest = CSRUtil.generateCSR(csrData);

        certificateInBytes = renewalOrModifyEntityCertificates(entityName, certificateRequest);
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYCERTMANAGEMENTRENEW", "CertMgmtRenewAndModifyEntityHandler",
                "Renew and modification of certificate done successfully for entity: " + entityName, "Renew and modify certificate(s) for entity",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return buildCommandResponse(certificateInBytes, entityName);
    }

    private byte[] renewalOrModifyEntityCertificates(final String entityName, final CertificateRequest certificateRequest) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, RevokedCertificateException, CertificateEncodingException {

        Certificate certificate = null;

        final String entityNameFilter = entityName.replaceAll(Constants.REPLACE_CHARACTERS, Constants.EMPTY_STRING);

        certificate = eServiceRefProxy.getEntityCertificateManagementService().renewCertificate(entityNameFilter, certificateRequest);

        if (certificate != null && certificate.getX509Certificate() != null) {
            return certificate.getX509Certificate().getEncoded();
        } else {
            throw new CertificateGenerationException("No certificate found");
        }

    }

    private PkiCommandResponse buildCommandResponse(final byte[] certificateInBytes, final String entityName) throws CertificateEncodingException {

        final String fileIdentifier = CliUtil.generateKey();

        final DownloadFileHolder downloadFileHolder = new DownloadFileHolder();
        downloadFileHolder.setFileName(entityName + Constants.CERTIFICATE_EXTENSION);
        downloadFileHolder.setContentType(Constants.CERTIFICATE_CONTENT_TYPE);
        downloadFileHolder.setContentToBeDownloaded(certificateInBytes);

        exportedItemsHolder.save(fileIdentifier, downloadFileHolder);

        logger.info("Downloadable content stored in memory with fileidentifier {}", fileIdentifier);

        final PkiDownloadRequestToScriptEngine commandResponse = new PkiDownloadRequestToScriptEngine();
        commandResponse.setFileIdentifier(fileIdentifier);

        return commandResponse;
    }

}
