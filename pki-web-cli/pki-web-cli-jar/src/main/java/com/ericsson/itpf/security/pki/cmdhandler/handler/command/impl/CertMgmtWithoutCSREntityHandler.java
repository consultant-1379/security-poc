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

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiDownloadRequestToScriptEngine;
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
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ContentType;
import com.ericsson.itpf.security.pki.cmdhandler.util.DownloadFileHolder;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * Handler implementation for CertMgmtWithoutCSREntityHandler. This provides service to generate certificate(s) for End entity without CSR
 *
 * "pkiadm" ( "certmgmt" | "ctm" ) "EECert" GENERATE "-nocsr" ENTITY_NAME FORMAT [ NO_CERTIFICATE_CHAIN ] GENERATE ::= ( "--generate" | "-gen" ) ENTITY_NAME ::= ( "--entityname" | "-en") " "
 * <entity_name> FORMAT ::= ( "--format" | "-f" ) " " ( ( ( "JKS" | "P12" ) [ PASSWORD ] ) | ( "PEM" ) ) NO_CERTIFICATE_CHAIN ::= ( "--nochain" | "-nch" )
 *
 * @author xpranma
 *
 */

@CommandType(PkiCommandType.ENTITYCERTMANAGEMENTGENARATEWITHOUTCSR)
@Local(CommandHandlerInterface.class)
public class CertMgmtWithoutCSREntityHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    @Inject
    FileUtility fileUtil;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    @Inject
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method implementation of CertMgmtWithoutCSREntityHandler. Handles command to generate certificate(s) for EndEntity without CSR
     *
     * @param command
     *
     * @return commandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {

        logger.info("ENTITYCERTMANAGEMENTGENARATEWITHOUTCSR command handler");

        PkiCommandResponse commandResponse = null;
        String format = null;
        String password = Constants.EMPTY_STRING;
        List<Certificate> certificates = new ArrayList<>();
        String keyStoreFilePath = null;
        try {

            final String entityName = command.getValueString(Constants.ENTITYNAME);
            if (ValidationUtils.isNullOrEmpty(entityName)) {
                return prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY);
            }

            format = command.getValueString(Constants.FORMAT);

            if (command.hasProperty(Constants.PASSWORD)) {
                password = command.getValueString(Constants.PASSWORD);
            }

            final KeyStoreInfo keyStoreInfo = eServiceRefProxy.getEntityCertificateManagementService().generateCertificate(entityName, password.toCharArray(), getFormat(format));

            if (command.hasProperty(Constants.NOCHAIN)) {
                keyStoreFilePath = CliUtil.getTempFile(entityName, "." + format.toLowerCase());
                pkiWebCliResourceLocalService.write(keyStoreFilePath, keyStoreInfo.getKeyStoreFileData(), false);

            } else {
                final CertificateChain certificateChain = eServiceRefProxy.getEntityCertificateManagementService().getCertificateChain(entityName);
                certificates = certificateChain.getCertificates();

                final X509Certificate[] x509certificateArray = createCertificateArray(certificates);

                keyStoreFilePath = createKeyStoreWithKey(format, password, entityName, keyStoreInfo, x509certificateArray);
            }

            commandResponse = buildCommandResponse(keyStoreFilePath);

        } catch (final AlgorithmNotFoundException algorithmNotFoundException) {
            logger.error(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException.getMessage());
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, algorithmNotFoundException);
            return prepareErrorMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CertificateGenerationException certificateGenerationException) {
            logger.error(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, certificateGenerationException.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION, certificateGenerationException);
            return prepareErrorMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION + Constants.SPACE_STRING
                    + certificateGenerationException.getMessage());
        } catch (final CertificateServiceException certificateServiceException) {
            logger.error(PkiErrorCodes.SERVICE_ERROR, certificateServiceException.getMessage());
            logger.debug(PkiErrorCodes.SERVICE_ERROR, certificateServiceException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, certificateServiceException);
        } catch (final InvalidCAException invalidCAException) {
            logger.error(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_CA_ENTITY, invalidCAException);
            return prepareErrorMessage(ErrorType.INVALID_CA_EXCEPTION.toInt(), invalidCAException.getMessage());
        } catch (final InvalidEntityException invalidEntityException) {
            logger.error(PkiErrorCodes.INVALID_ENTITY, invalidEntityException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityException.getMessage());
        } catch (final InvalidEntityAttributeException invalidEntityAttributeException) {
            logger.error(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ENTITY, invalidEntityAttributeException);
            return prepareErrorMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY + invalidEntityAttributeException.getMessage());
        } catch (final IOException iOException) {
            logger.error(PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE, iOException.getMessage());
            logger.debug(PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE, iOException);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE + Constants.SPACE_STRING + iOException.getMessage(), iOException);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.error(PkiErrorCodes.ENTITY_DOES_NOT_EXIST, entityNotFoundException.getMessage());
            logger.debug(PkiErrorCodes.ENTITY_DOES_NOT_EXIST, entityNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_DOES_NOT_EXIST);
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, noSuchAlgorithmException.getMessage());
            logger.debug(PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION, noSuchAlgorithmException);
            return prepareErrorMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION);
        } catch (final CommandSyntaxException commandSyntaxException) {
            logger.error(PkiErrorCodes.SYNTAX_ERROR, commandSyntaxException.getMessage());
            logger.debug(PkiErrorCodes.SYNTAX_ERROR, commandSyntaxException);
            return prepareErrorMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), PkiErrorCodes.SYNTAX_ERROR + Constants.SPACE_STRING + commandSyntaxException.getMessage(), commandSyntaxException);
        } catch (final KeyStoreException | CertificateException exception) {
            logger.error(PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON, exception.getMessage());
            logger.debug(PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON, exception);
            return prepareErrorMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON + Constants.SPACE_STRING + exception.getMessage(), exception);
        } catch (final IllegalArgumentException illegalArgumentException) {
            logger.error(PkiErrorCodes.INVALID_ARGUMENT, illegalArgumentException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_ARGUMENT, illegalArgumentException);
            return prepareErrorMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.INVALID_ARGUMENT + Constants.SPACE_STRING + illegalArgumentException.getMessage(),
                    illegalArgumentException);
        } catch (final ExpiredCertificateException expiredCertificateException) {
            logger.error(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException.getMessage());
            logger.debug(PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION, expiredCertificateException);
            return prepareErrorMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION);
        } catch (final InvalidCertificateStatusException invalidCertificateStatusException) {
            logger.error(PkiErrorCodes.INVALID_CERTIFICATE_STATUS, invalidCertificateStatusException.getMessage());
            logger.debug(PkiErrorCodes.INVALID_CERTIFICATE_STATUS, invalidCertificateStatusException);
            return prepareErrorMessage(ErrorType.INVALID_CERTIFICATE_STATUS_EXCEPTION.toInt(), invalidCertificateStatusException.getMessage());
        } catch (final RevokedCertificateException revokedCertificateException) {
            logger.error(PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION, revokedCertificateException.getMessage());
            logger.debug(PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION, revokedCertificateException);
            return prepareErrorMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException.getMessage());
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            logger.error(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, exception.getMessage());
            logger.debug(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, exception);
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordEvent("PKISERVICE.ENTITYCERTIFICATEMANAGEMENTSERVICE", EventLevel.COARSE, "PKI.ENTITYCERTMANAGEMENTGENARATEWITHOUTCSR", "Entity for which certificate generated: "
                + command.getValueString(Constants.ENTITYNAME), "Certificate generated successfully for Entity without CSR provided.");
        return commandResponse;
    }

    private X509Certificate[] createCertificateArray(final List<Certificate> certificates) throws CertificateGenerationException {

        X509Certificate[] x509certificateArray = null;

        if (certificates == null) {
            throw new CertificateGenerationException();
        }

        final ArrayList<X509Certificate> x509certificateList = new ArrayList<>();
        x509certificateArray = new X509Certificate[certificates.size()];

        for (final Certificate certificate : certificates) {
            x509certificateList.add(certificate.getX509Certificate());
        }

        x509certificateArray = x509certificateList.toArray(x509certificateArray);
        return x509certificateArray;

    }

    private String createKeyStoreWithKey(final String format, final String password, final String entityName, final KeyStoreInfo keyStoreInfo, final X509Certificate[] x509certificateChain)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        FileOutputStream out = null;
        String keyStoreFilePath = null;
        try {
            keyStoreFilePath = createKeyStoreFilePath(format, entityName);

            out = new FileOutputStream(keyStoreFilePath);

            final KeyStore keyStore = fetchKeyFromKeyStore(keyStoreInfo, format, password);
            final Key privateKey = keyStore.getKey(keyStoreInfo.getAlias(), password.toCharArray());
            keyStore.deleteEntry(keyStoreInfo.getAlias());
            keyStore.setKeyEntry(keyStoreInfo.getAlias(), privateKey, password.toCharArray(), x509certificateChain);

            keyStore.store(out, password.toCharArray());

        } catch (final UnrecoverableKeyException unrecoverableKeyException) {
            logger.debug(PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON, unrecoverableKeyException);
            throw new KeyStoreException();
        }

        finally {
            if (out != null) {
                out.close();
            }
        }

        return keyStoreFilePath;
    }

    /**
     *
     * @param format
     * @param entityName
     * @return
     */
    private String createKeyStoreFilePath(final String format, final String entityName) {

        String keyStoreFilePath = null;

        switch (getFormat(format)) {
        case JKS:
            keyStoreFilePath = Constants.TMP_DIR + Constants.FILE_SEPARATOR + entityName + Constants.JKS_EXTENSION;
            break;
        case PKCS12:
            keyStoreFilePath = Constants.TMP_DIR + Constants.FILE_SEPARATOR + entityName + Constants.P12_EXTENSION;
            break;
        default:
            logger.error("Unsupported keystore type {}", format);
            throw new IllegalArgumentException("keystore is not supported");
        }

        return keyStoreFilePath;

    }

    private KeyStore fetchKeyFromKeyStore(final KeyStoreInfo keyStoreInfo, final String format, final String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException {

        KeyStore ks = null;
        ByteArrayInputStream fis = null;
        try {
            final String name = getFormat(format).value();
            if (format.equals(Constants.P12_FORMAT)) {
                ks = KeyStore.getInstance(name.toUpperCase(), new BouncyCastleProvider());
            } else {
                ks = KeyStore.getInstance(name.toUpperCase());
            }
            fis = new ByteArrayInputStream(keyStoreInfo.getKeyStoreFileData());
            ks.load(fis, password.toCharArray());
        } finally {

            if (fis != null) {
                fis.close();
            }
        }
        return ks;
    }

    private KeyStoreType getFormat(final String format) {

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
        default:
            throw new IllegalArgumentException("Format is not supported");
        }
        return keyStoreType;
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
        downloadFileHolder.setContentType(ContentType.valueOf(fileName.substring(fileName.lastIndexOf('.') + 1).toUpperCase()).value());

        return downloadFileHolder;
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error: {} occured when generating Entity certificate without csr: {}", PkiWebCliException.ERROR_CODE_START_INT + errorCode, cause);
        return PkiCommandResponse.message(errorCode, errorMessage, cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured when generating Entity certificate without csr: {}", PkiWebCliException.ERROR_CODE_START_INT + errorCode, errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage, Constants.EMPTY_STRING);
    }

}