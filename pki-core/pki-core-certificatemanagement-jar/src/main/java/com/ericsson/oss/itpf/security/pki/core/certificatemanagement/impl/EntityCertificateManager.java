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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CRMFRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.generator.CertificateGenerator;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler.CertificateRequestPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.qualifier.CertificateManagerType;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.qualifier.EntityTypeEnum;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.AlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExistsException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 * Class for the certificate management operations for Entity.
 *
 */
// TODO : Other validators may included in this class e.g : CSR, Entity etc. User story ref : TORF-59437
// TODO Refactor CRMF design, this comment will be addressed as part of TORF-70743

@CertificateManagerType(EntityTypeEnum.ENTITY)
public class EntityCertificateManager implements CertificateManager {

    @Inject
    CertificatePersistenceHelper persistenceHelper;

    @Inject
    Logger logger;

    @Inject
    CertificateGenerator certGenerator;

    @Inject
    ExtensionBuilder extensionBuilder;

    @Inject
    AlgorithmValidator algorithmValidator;

    @Inject
    CertificateModelMapper modelMapper;

    @Inject
    CertificateRequestPersistenceHandler certificateRequestPersistenceHandler;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Generates certificate from {@link CertificateGenerationInfo} passed. This method takes {@link PublicKey} and {@link PKCS10CertificationRequest} from {@link CertificateGenerationInfo} for
     * entity. Certificate is generated from CSR and {@link CertificateGenerationInfo}. Certificate is signed with issuer private key. If in case active certificate exists then it makes it inactive
     * and regenerates a new certificate.
     *
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} passed to generate a certificate.
     * @throws AlgorithmValidationException
     *             in case of Algorithm validation is failed.
     * @throws CertificateExistsException
     *             in case of certificate already exists in the system.
     * @throws CertificateGenerationException
     *             in case of any issues during certificate generation
     * @throws CertificateServiceException
     *             in case of internal db error while certificate creation
     * @throws CoreEntityNotFoundException
     *             in case of entity is not present in the system.
     * @throws CoreEntityServiceException
     *             in case of internal db error while entity validation
     * @throws InvalidCertificateException
     *             thrown when Invalid certificate is found for entity.
     * @throws InvalidCertificateRequestException
     *             in case of any issues with CSR in {@link CertificateGenerationInfo}
     * @throws UnsupportedCertificateVersionException
     *             in case the provided Certificate version is not supported
     */
    @Override
    public Certificate generateCertificate(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateGenerationException, CertificateServiceException,
            CoreEntityNotFoundException, CoreEntityServiceException, InvalidCertificateRequestException, UnsupportedCertificateVersionException {

        logger.debug("Generating Certificate for end entity {}", certificateGenerationInfo.getEntityInfo().getName());
        algorithmValidator.validateAlgorithm(certificateGenerationInfo.getKeyGenerationAlgorithm());
        algorithmValidator.validateAlgorithm(certificateGenerationInfo.getSignatureAlgorithm());
        algorithmValidator.validateAlgorithm(certificateGenerationInfo.getIssuerSignatureAlgorithm());

        final EntityInfo entityInfo = certificateGenerationInfo.getEntityInfo();
        final EntityInfoData entityData = persistenceHelper.getEntityData(entityInfo.getName());
        if (entityData == null) {
            logger.info("Entity [{}] not found in pkicoredb", entityInfo.getName());
            throw new CoreEntityNotFoundException("Entity [" + entityInfo.getName() + "] not found in pkicoredb");
        }

        final CertificateAuthorityData issuerCA = persistenceHelper.getCA(certificateGenerationInfo.getIssuerCA().getName());

        try {
            final PublicKey publicKey = getPublicKey(certificateGenerationInfo);

            final List<Extension> certificateExtensions = extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey);

            final KeyIdentifier keyIdentifier = persistenceHelper.getKeyIdentifier(certificateGenerationInfo.getIssuerCA().getName());

            final X509Certificate x509Certificate = certGenerator.generateCertificate(certificateGenerationInfo, keyIdentifier, publicKey, certificateExtensions);

            final CertificateData certificateData = persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, null, issuerCA, null);

            persistenceHelper.updateEntityData(certificateData, entityData, issuerCA, EntityStatus.ACTIVE);
            final CertificateGenerationInfoData certificateGenerationInfoData = validateAndStoreCertificateGenerationInfo(certificateGenerationInfo, entityData, certificateData);
            persistenceHelper.updateCSR(certificateGenerationInfoData.getCertificateRequestData());

            final Certificate certificate = modelMapper.mapToCertificate(certificateData);
            logger.debug("Certificate generated for end entity {}", certificateGenerationInfo.getEntityInfo().getName());
            return certificate;

        } catch (final IOException ioException) {
            logger.error(ErrorMessages.IO_EXCEPTION, ioException.getMessage());
            logger.debug(ErrorMessages.IO_EXCEPTION, ioException);
            systemRecorder.recordError("PKISERVICE.ENTITYCERTIFICATEMANAGEMENTSERVICE_FAILED", ErrorSeverity.ERROR, "PKI.EntityCertificateManager", "ENTITY_CERTIFICATE_GENERATION",
                    "Issue with provided input for entity " + certificateGenerationInfo.getEntityInfo().getName());
            throw new CertificateGenerationException(ErrorMessages.IO_EXCEPTION + ioException.getMessage());
        } catch (final CertificateException e) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, e.getMessage());
            logger.debug(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, e);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "EntityCertificateManager", "Certificate encoding for entity " + certificateGenerationInfo.getEntityInfo().getName()
                    + " is invalid", "EntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION);
        } catch (final InvalidCertificateException invalidCertificateException) {
            logger.error("Certificate of the entity is invaid : {}", invalidCertificateException.getMessage());
            logger.debug("Certificate of the entity is invaid : {}", invalidCertificateException);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "EntityCertificateManager", "Certifacte of entity " + certificateGenerationInfo.getEntityInfo().getName()
                    + " is invalid", "EntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(invalidCertificateException);
        } catch (final InvalidCertificateExtensionsException invalidCertificateExtensionsException) {
            logger.error(ErrorMessages.INVALID_CERTIFICATE_EXTENSIONS, invalidCertificateExtensionsException.getMessage());
            logger.debug(ErrorMessages.INVALID_CERTIFICATE_EXTENSIONS, invalidCertificateExtensionsException);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "EntityCertificateManager", "Certifacte of entity " + certificateGenerationInfo.getEntityInfo().getName()
                    + " has invalid extensions", "EntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(invalidCertificateExtensionsException);
        } catch (final KeyPairGenerationException keyPairGenerationException) {
            logger.error("Key Pair could not be generated : {}", keyPairGenerationException.getMessage());
            logger.debug("Key Pair could not be generated : {}", keyPairGenerationException);
            systemRecorder.recordSecurityEvent("Certificate Management Service", "EntityCertificateManager", "Exception occured while generating Key Pair for entity "
                    + certificateGenerationInfo.getEntityInfo().getName(), "EntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new CertificateGenerationException(keyPairGenerationException);
        }
    }

    private CertificateGenerationInfoData validateAndStoreCertificateGenerationInfo(final CertificateGenerationInfo certificateGenerationInfo, final EntityInfoData entityData,
            final CertificateData certificateData) throws IOException, CertificateGenerationException, CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException {

        PKCS10CertificationRequest certificateRequest = null;
        CertificateRequestMessage certificateRequestMessage = null;
        CertificateGenerationInfoData certificateGenerationInfoData = null;

        if (certificateGenerationInfo.getCertificateRequest().getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {

            final PKCS10CertificationRequestHolder certificationRequestHolder = (PKCS10CertificationRequestHolder) certificateGenerationInfo.getCertificateRequest().getCertificateRequestHolder();
            certificateRequest = certificationRequestHolder.getCertificateRequest();
            certificateGenerationInfoData = certificateRequestPersistenceHandler
                    .storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequest.getEncoded(), entityData, certificateData);
        } else {

            final CRMFRequestHolder certificationRequestHolder = (CRMFRequestHolder) certificateGenerationInfo.getCertificateRequest().getCertificateRequestHolder();
            certificateRequestMessage = certificationRequestHolder.getCertificateRequest();
            certificateGenerationInfoData = certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestMessage.getEncoded(), entityData,
                    certificateData);
        }
        return certificateGenerationInfoData;
    }

    private PublicKey getPublicKey(final CertificateGenerationInfo certificateGenerationInfo) throws IOException, InvalidCertificateRequestException {

        PublicKey publicKey = null;

        try {
            if (certificateGenerationInfo.getCertificateRequest().getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
                final PKCS10CertificationRequestHolder certificationRequestHolder = (PKCS10CertificationRequestHolder) certificateGenerationInfo.getCertificateRequest().getCertificateRequestHolder();
                final PKCS10CertificationRequest pkcs10CertificationRequest = certificationRequestHolder.getCertificateRequest();
                final JcaPKCS10CertificationRequest cSR = new JcaPKCS10CertificationRequest(pkcs10CertificationRequest.getEncoded());
                publicKey = cSR.getPublicKey();
            } else {
                final CRMFRequestHolder certificationRequestHolder = (CRMFRequestHolder) certificateGenerationInfo.getCertificateRequest().getCertificateRequestHolder();
                final CertificateRequestMessage certificateRequestMessage = certificationRequestHolder.getCertificateRequest();
                final JcaCertificateRequestMessage cSR = new JcaCertificateRequestMessage(certificateRequestMessage.getEncoded());
                publicKey = cSR.getPublicKey();
            }

            return publicKey;
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.NO_SUCH_AlGORITHM, noSuchAlgorithmException.getMessage());
            logger.debug(ErrorMessages.NO_SUCH_AlGORITHM, noSuchAlgorithmException);
            throw new InvalidCertificateRequestException(ErrorMessages.NO_SUCH_AlGORITHM + noSuchAlgorithmException.getMessage());
        } catch (final InvalidKeyException invalidKeyException) {
            logger.error(ErrorMessages.INVALID_KEY, invalidKeyException);
            logger.debug(ErrorMessages.INVALID_KEY, invalidKeyException.getMessage());
            throw new InvalidCertificateRequestException(invalidKeyException.getMessage());
        } catch (final CRMFException crmfException) {
            logger.error(ErrorMessages.CRMF_EXCEPTION, crmfException.getMessage());
            logger.debug(ErrorMessages.CRMF_EXCEPTION, crmfException);
            throw new InvalidCertificateRequestException(ErrorMessages.CRMF_EXCEPTION + crmfException.getMessage());
        }
    }
}
