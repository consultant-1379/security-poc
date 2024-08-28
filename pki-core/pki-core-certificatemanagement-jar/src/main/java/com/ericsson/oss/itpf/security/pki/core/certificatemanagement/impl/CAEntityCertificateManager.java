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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.generator.CertificateGenerator;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler.CertificateRequestPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.qualifier.CertificateManagerType;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.qualifier.EntityTypeEnum;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.AlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.ImportCertificateCAValidator;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.KeyIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.KeyIdentifierData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.ImportCertificatePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 * Class for the certificate management operations for CA Entity
 */
// TODO : Other validators may included in this class e.g : CSR, Entity etc. User story ref : TORF-59437
@CertificateManagerType(EntityTypeEnum.CA_ENTITY)
public class CAEntityCertificateManager implements CertificateManager {

    @Inject
    CertificatePersistenceHelper persistenceHelper;

    @Inject
    Logger logger;

    @Inject
    CertificateGenerator certGenerator;

    @Inject
    ExtensionBuilder extensionBuilder;

    @Inject
    CertificateGenerationInfoParser certGenInfoParser;

    @Inject
    AlgorithmValidator algorithmValidator;

    @Inject
    ImportCertificateCAValidator importCertificateCAValidator;

    @Inject
    CertificateModelMapper modelMapper;

    @Inject
    CertificateRequestPersistenceHandler certificateRequestPersistenceHandler;

    @Inject
    ImportCertificatePersistenceHandler importCertificatePersistenceHandler;

    @Inject
    KeyIdentifierModelMapper keyIdentifierModelMapper;

    @Inject
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    @Inject
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Generates certificate from {@link CertificateGenerationInfo} passed. This method generates {@link KeyPair} and {@link PKCS10CertificationRequest} for CA entity. Certificate is generated from
     * CSR and {@link CertificateGenerationInfo}. For Root CA, certificate is signed with its own private key. For Sub CAs, certificate is signed with issuer private key.
     *
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} passed to generate a certificate.
     * @throws AlgorithmValidationException
     *             in case of Algorithm validation is failed.
     * @throws CertificateGenerationException
     *             in case of any issues during certificate generation
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CertificateServiceException
     *             in case of internal db error
     * @throws CoreEntityNotFoundException
     *             in case of entity not found in the system.
     * @throws CoreEntityServiceException
     *             in case of db error for entity related operations.
     * @throws InvalidCertificateExtensionsException
     *             in case of certificate extensions passed in {@link CertificateGenerationInfo} are not valid.
     * @throws InvalidCertificateRequestException
     *             in case of invalid CSR is provided.
     * @throws KeyPairGenerationException
     *             when KeyPair generation has failed
     *
     */
    @Override
    public Certificate generateCertificate(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException {

        logger.debug("Generating Certificate for CA Entity {} ", certificateGenerationInfo.getCAEntityInfo().getName());
        algorithmValidator.validateAlgorithm(certificateGenerationInfo.getKeyGenerationAlgorithm());
        algorithmValidator.validateAlgorithm(certificateGenerationInfo.getSignatureAlgorithm());
        algorithmValidator.validateAlgorithm(certificateGenerationInfo.getIssuerSignatureAlgorithm());

        try {
            final KeyIdentifierData keyIdentifierData = getKeyIdentifierOfCA(certificateGenerationInfo);
            final KeyIdentifier keyIdentifier = keyIdentifierModelMapper.toModel(keyIdentifierData);
            final PublicKey publicKey = keyAccessProviderServiceProxy.getKeyAccessProviderService().getPublicKey(keyIdentifier);

            final PKCS10CertificationRequestHolder certificateRequestHolder = keyAccessProviderServiceProxy.getKeyAccessProviderService().generateCSR(keyIdentifier,
                    certificateGenerationInfo.getSignatureAlgorithm().getName(), certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateGenerationInfo), null);

            final CertificateAuthorityData certificateAuthorityData = persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName());

            final List<Extension> certificateExtensions = extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey);

            final X509Certificate x509Certificate = generateCertificate(certificateGenerationInfo, keyIdentifier, publicKey, certificateExtensions);

            CertificateAuthorityData issuerCAData = null;
            if (!certificateGenerationInfo.getCAEntityInfo().isRootCA()) {
                issuerCAData = persistenceHelper.getCA(certificateGenerationInfo.getIssuerCA().getName());
            }

            final CertificateData certificateData = persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, certificateAuthorityData, issuerCAData, keyIdentifierData);

            final Certificate certificate = modelMapper.mapToCertificate(certificateData);

            persistenceHelper.updateCAWithActiveCertificate(certificateData, certificateAuthorityData, issuerCAData, CAStatus.ACTIVE);
            persistenceHelper.updateCAWithActiveKeys(certificateAuthorityData, keyIdentifierData);

            final CertificateGenerationInfoData certificateGenerationInfoData = certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestHolder
                    .getCertificateRequest().getEncoded(), certificateAuthorityData, null, certificateData);

            persistenceHelper.updateCSR(certificateGenerationInfoData.getCertificateRequestData());

            return certificate;
        } catch (final IOException ioException) {
            logger.debug(ErrorMessages.INVALID_CSR_ENCODING, ioException);
            logger.error("{} for {}", ErrorMessages.INVALID_CSR_ENCODING, certificateGenerationInfo.getCAEntityInfo().getName());
            systemRecorder.recordError("PKISERVICE.CACERTIFICATEMANAGEMENTSERVICE_FAILED", ErrorSeverity.ERROR, "PKI.CAEntityCertificateManager", "CA_ENTITY_CERTIFICATE_GENERATION",
                    "CSR encoding is not valid or not in correct format for " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateGenerationException(ErrorMessages.INVALID_CSR_ENCODING);
        } catch (final CertificateException certificateException) {
            logger.debug(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, certificateException);
            logger.error("{} for {} ", ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, certificateGenerationInfo.getCAEntityInfo().getName());
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "Certificate encoding for CA entity "
                    + certificateGenerationInfo.getCAEntityInfo().getName() + " is invalid", "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION);
        } catch (final KeyIdentifierNotFoundException exception) {
            logger.error(ErrorMessages.UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER + certificateGenerationInfo.getCAEntityInfo().getName(), exception);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "Active key pair with given key identifier for CA entity "
                    + certificateGenerationInfo.getCAEntityInfo().getName() + " not found", "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(ErrorMessages.UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER + certificateGenerationInfo.getCAEntityInfo().getName());
        } catch (final KeyAccessProviderServiceException exception) {
            logger.error(ErrorMessages.UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER + certificateGenerationInfo.getCAEntityInfo().getName(), exception);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "An internal Exception occured while accessing KAPSDB", "CAEntityCertificateGenetation",
                    ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateServiceException(ErrorMessages.UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER + certificateGenerationInfo.getCAEntityInfo().getName());
        } catch (final com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException csrGenerationException) {
            logger.debug(ErrorMessages.UNABLE_TO_GENERATE_CSR_FOR_CA_FROM_KAPS, csrGenerationException);
            logger.error(ErrorMessages.UNABLE_TO_GENERATE_CSR_FOR_CA_FROM_KAPS, certificateGenerationInfo.getCAEntityInfo().getName());
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "CSR for CA entity " + certificateGenerationInfo.getCAEntityInfo().getName()
                    + " can not be generated", "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(ErrorMessages.UNABLE_TO_GENERATE_CSR_FOR_CA_FROM_KAPS + certificateGenerationInfo.getCAEntityInfo().getName());
        } catch (final InvalidCertificateException invalidCertificateException) {
            logger.error(ErrorMessages.INVALID_CERTTIFICATE_EXCEPTION, invalidCertificateException.getMessage());
            logger.debug(ErrorMessages.INVALID_CERTTIFICATE_EXCEPTION, invalidCertificateException);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "Certifacte of CA entity " + certificateGenerationInfo.getCAEntityInfo().getName()
                    + " is invalid", "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(invalidCertificateException.getMessage(), invalidCertificateException);
        } catch (final InvalidCertificateExtensionsException invalidCertificateExtensionsException) {
            logger.error(ErrorMessages.INVALID_CERTIFICATE_EXTENSIONS, invalidCertificateExtensionsException.getMessage());
            logger.debug(ErrorMessages.INVALID_CERTIFICATE_EXTENSIONS, invalidCertificateExtensionsException);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "Certifacte of CA entity " + certificateGenerationInfo.getCAEntityInfo().getName()
                    + " has invalid extensions", "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(invalidCertificateExtensionsException.getMessage(), invalidCertificateExtensionsException);
        } catch (final KeyPairGenerationException keyPairGenerationException) {
            logger.error(keyPairGenerationException.getMessage());
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "Exception occured while generating Key Pair for CA entity "
                    + certificateGenerationInfo.getCAEntityInfo().getName(), "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(keyPairGenerationException.getMessage(), keyPairGenerationException);
        } catch (final UnsupportedCertificateVersionException unsupportedCertificateVersionException) {
            logger.error(unsupportedCertificateVersionException.getMessage());
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "Certifacte version of CA entity "
                    + certificateGenerationInfo.getCAEntityInfo().getName() + " is not supported", "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(unsupportedCertificateVersionException.getMessage(), unsupportedCertificateVersionException);
        } catch (final Exception exception) {
            logger.error(exception.getMessage());
            systemRecorder.recordSecurityEvent("Certificate Management Service", "CAEntityCertificateManager", "Unknown error has occured for "
                    + certificateGenerationInfo.getCAEntityInfo().getName(), "CAEntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(exception.getMessage(), exception);
        }
    }

    private X509Certificate generateCertificate(final CertificateGenerationInfo certificateGenerationInfo, final KeyIdentifier keyIdentifier, final PublicKey publicKey,
            final List<Extension> certificateExtensions) throws CertificateGenerationException, CoreEntityNotFoundException, InvalidCertificateExtensionsException,
            UnsupportedCertificateVersionException {

        logger.debug("Generating Certificate for entity : {}", certificateGenerationInfo.getCAEntityInfo().getName());
        X509Certificate certificate;
        if (certificateGenerationInfo.getCAEntityInfo().isRootCA()) {
            logger.info("CA Entity '{}' requested for Certificate Generation is a Root CA", certificateGenerationInfo.getCAEntityInfo().getName());
            certificate = certGenerator.generateCertificate(certificateGenerationInfo, keyIdentifier, publicKey, certificateExtensions);
        } else {
            final KeyIdentifier issuerKeyIdentifier = persistenceHelper.getKeyIdentifier(certificateGenerationInfo.getIssuerCA().getName());

            certificate = certGenerator.generateCertificate(certificateGenerationInfo, issuerKeyIdentifier, publicKey, certificateExtensions);
        }
        return certificate;
    }

    private KeyIdentifierData getKeyIdentifierOfCA(final CertificateGenerationInfo certificateGenerationInfo) throws CertificateServiceException, CoreEntityNotFoundException,
            KeyPairGenerationException {

        final KeyIdentifierData keyIdentifierData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);
        systemRecorder.recordEvent("PKISERVICE.CACERTIFICATEMANAGEMENTSERVICE_FAILED", EventLevel.COARSE, "PKI.CAEntityCertificateManager", "CA_ENTITY_CERTIFICATE_GENERATION",
                "Active key identifier retrieved for CA successfully");
        return keyIdentifierData;
    }

}
