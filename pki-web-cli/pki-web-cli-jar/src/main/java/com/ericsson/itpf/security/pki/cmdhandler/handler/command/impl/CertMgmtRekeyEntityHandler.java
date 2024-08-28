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

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

import javax.ejb.Local;
import javax.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.*;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * Handler implementation for CertMgmtRekeyEntityHandler. This provides service to rekey certificate(s) for end entity.
 *
 * @author xpranma
 */
@Local(CommandHandlerInterface.class)
public class CertMgmtRekeyEntityHandler implements CommandHandlerInterface  {

    @Inject
    CliUtil cliUtil;

    @Inject
    protected Logger logger;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
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
     * @throws InvalidEntityException
     *             This exception is thrown to indicate invalid entity
     * @throws KeyPairGenerationException
     *             This exception indicates exception during keypair generation
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws ExpiredCertificateException
     * @throws InvalidEntityAttributeException
     * @throws RevokedCertificateException
     */
    public PkiCommandResponse rekeyHandler(final PkiPropertyCommand command, final String entityName) throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException,
            EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {

        logger.info("ENTITYCERTMANAGEMENTRENEW command handler with update type as re-key");

        byte[] certificateInBytes = null;

        PkiCommandResponse commandResponse = null;

        final String password = command.getValueString(Constants.PASSWORD);
        if (ValidationUtils.isNullOrEmpty(password)) {
            return cliUtil.prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), "Password cannot be empty", null);
        }

        final String format = command.getValueString(Constants.FORMAT);
        if (ValidationUtils.isNullOrEmpty(format)) {
            return cliUtil.prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), "Invalid format or null", null);
        }

        final KeyStoreInfo keyStoreInfo = reKeyEntityCertificate(entityName, password, format);

        if (keyStoreInfo != null) {
            certificateInBytes = keyStoreInfo.getKeyStoreFileData();
        }

        final String keyStoreFilePath = writeIntoKeyStore(certificateInBytes, entityName, format, password);

        commandResponse = buildPkiCommandResponse(pkiWebCliResourceLocalService.getBytesAndDelete(keyStoreFilePath), entityName, format);
        systemRecorder.recordSecurityEvent("PKIWebCLI.ENTITYCERTMANAGEMENTREKEY", "CertMgmtRekeyEntityHandler",
                "Rekey of Certificate is successfull for End Entity: " + entityName, "Rekey certificate(s) for end entity",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return commandResponse;

    }

    /**
     * @param format
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    private String writeIntoKeyStore(final byte[] certificateInBytes, final String entityName, final String format, final String password)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        KeyStore ks = null;
        ByteArrayInputStream fis = null;
        FileOutputStream fos = null;
        String keyStoreFilePath = null;

        final String name = getFormat(format).value();
        if (format.equals(Constants.P12_FORMAT)) {
            ks = KeyStore.getInstance(name.toUpperCase(), new BouncyCastleProvider());
        } else {
            ks = KeyStore.getInstance(name.toUpperCase());
        }

        try {
            fis = new ByteArrayInputStream(certificateInBytes);
            ks.load(fis, password.toCharArray());
            keyStoreFilePath = getTempFile(entityName, "." + format.toLowerCase());

            fos = new FileOutputStream(keyStoreFilePath);
            ks.store(fos, password.toCharArray());
        } finally {
            closeInputStream(fis);
            closeOutputStream(fos);
        }
        return keyStoreFilePath;
    }

    public KeyStoreType getFormat(final String format)

    {
        KeyStoreType keyStoreType = null;

        switch (format) {
            case Constants.JKS_FORMAT:
                keyStoreType = KeyStoreType.JKS;
                break;

            case Constants.P12_FORMAT:
                keyStoreType = KeyStoreType.PKCS12;
                break;

            case Constants.PEM_FORMAT:
                keyStoreType = KeyStoreType.PEM;
                break;

            case Constants.JCEKS_FORMAT:
                keyStoreType = KeyStoreType.JCEKS;
                break;
        }
        return keyStoreType;
    }

    public static String getTempFile(final String fileName, final String fileExtension) {
        return Constants.TMP_DIR + Constants.FILE_SEPARATOR + fileName + fileExtension;
    }

    private KeyStoreInfo reKeyEntityCertificate(final String entityName, final String password, final String format) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        final String entityNameFilter = entityName.replaceAll(Constants.REPLACE_CHARACTERS, Constants.EMPTY_STRING);

        return eServiceRefProxy.getEntityCertificateManagementService().reKeyCertificate(entityNameFilter, password.toCharArray(), getFormat(format));
    }

    private PkiCommandResponse buildPkiCommandResponse(final byte[] fileContents, final String entityName, final String format) {
        final String fileIdentifier = CliUtil.generateKey();
        final DownloadFileHolder downloadFileHolder = generateDownloadFileHolder(entityName, format);
        downloadFileHolder.setContentToBeDownloaded(fileContents);
        exportedItemsHolder.save(fileIdentifier, downloadFileHolder);
        logger.info("Downloadable content stored in memory with fileidentifier {}", fileIdentifier);

        final PkiDownloadRequestToScriptEngine commandResponse = new PkiDownloadRequestToScriptEngine();
        commandResponse.setFileIdentifier(fileIdentifier);
        return commandResponse;
    }

    private DownloadFileHolder generateDownloadFileHolder(final String entityName, final String format) {

        final DownloadFileHolder downloadFileHolder = new DownloadFileHolder();
        downloadFileHolder.setFileName(entityName + "." + format.toLowerCase());
        downloadFileHolder.setContentType(ContentType.valueOf(format).value());

        return downloadFileHolder;
    }

    private void closeInputStream(final ByteArrayInputStream fis) throws IOException {
        if (fis != null) {
            try {
                fis.close();
            } catch (Exception e) {
                logger.error("Unable to close the file Input stream");
                throw e;
            }
        }
    }

    private void closeOutputStream(final FileOutputStream fos) throws IOException {
        if (fos != null) {
            try {
                fos.close();
            } catch (Exception e) {
                logger.error("Unable to close the file output stream");
                throw e;
            }
        }
    }
}
