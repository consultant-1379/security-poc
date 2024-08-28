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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CRMFRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.notifier.CertificateEventNotifier;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.AlgorithmCompatibilityValidator;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.CertificateRequestParser;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.KeyStoreUtil;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CRMFValidator;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateRequestValidator;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.utils.CertificateServiceExceptionUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SdkResourceManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Class used for generating and listing the certificates of Entities.
 *
 * <p>
 * Generating certificates, get the Entity, apply overriding scenarios for subject and subjectAltName and build the {@link CertificateGenerationInfo} object and pass on to PKI-Core, which will
 * generate the certificate.
 *
 * Listing of certificates, return the list of certificates of CAEntity based on certificate status.
 * </p>
 */
public class EntityCertificateManager extends AbstractCertificateManager {

    // TODO Refactor CRMF design, this comment will be addressed as part of TORF-70743

    @Inject
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;

    @EJB
    SdkResourceManagementLocalService sdkResourceManagementLocalService;

    @Inject
    CertificateGenerationInfoBuilder certificateInfoBuilder;

    @Inject
    CertificateValidator certificateValidator;

    @Inject
    CertificateRequestValidator certificateRequestValidator;

    @Inject
    TDPSPersistenceHandler tdpsPersistenceHandler;

    @Inject
    CertificateEventNotifier certificateEventNotifier;

    @Inject
    KeyStoreUtil keyStoreUtil;

    @Inject
    EntityHelper entityHelper;

    @Inject
    CRMFValidator crmfValidator;

    @Inject
    AlgorithmCompatibilityValidator algorithmCompatibilityValidator;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Generate certificate for Entity with CSR. The newly generated certificate will automatically be published to TDPS.
     *
     * @param entityName
     *            The entity name.
     * @param certificateRequest
     *            The CSR containing either PKCS10/CRMF request.
     * @param requestType
     *            type of the certificate request.
     * @return Certificate
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidCertificateRequestException
     *             Thrown to indicate that the given Certificate Request is not valid.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid entity Attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public Certificate generateCertificate(final String entityName, final CertificateRequest certificateRequest, final RequestType requestType) throws AlgorithmNotFoundException,
            CertificateGenerationException, CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException,
            InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        final Entity entity = entityHelper.getEntity(entityName);
        validateCertificateRequest(certificateRequest, entity);

        try {

            if (requestType == RequestType.RENEW) {
                certificateValidator.verifyEntityStatusForReissue(entity);
            }
            certificateValidator.validateIssuerChain(entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName());
            // TORF-143242 - Removing DNQ from the Certificate unblock the AMOS issue
            SubjectUtils.removeDNQFromSubject(entity.getEntityInfo().getSubject());
            entityHelper.setEntitySubject(certificateRequest, entity);
            entityHelper.setEntitySubjectAltName(certificateRequest, entity);

            final String csrKeyGenerationAlgorithm = CertificateRequestParser.extractKeyGenerationAlgorithm(certificateRequest);
            logger.info("Key generation algorithm {} from CSR", csrKeyGenerationAlgorithm);

            entity.setKeyGenerationAlgorithm(entityHelper.validateAndGetAlgorithmModel(entity, csrKeyGenerationAlgorithm));

            final CertificateGenerationInfo certificateGenerateInfo = certificateInfoBuilder.build(entity, requestType);
            certificateGenerateInfo.setCertificateRequest(certificateRequest);

            entityCertificatePersistenceHelper.storeCertificateGenerateInfo(certificateGenerateInfo);

            logger.debug("Calling pki core to generate certificate for Entity {}", entityName);
            final Certificate certificate = certificatemanagementEserviceProxy.getCoreCertificateManagementService().createCertificate(certificateGenerateInfo);
            logger.info("PKI core returned the certificate, serial number is {}", certificate.getSerialNumber());

            entityCertificatePersistenceHelper.storeCertificate(entity, certificateGenerateInfo, certificate);

            if (entity.isPublishCertificatetoTDPS()) {
                certificateEventNotifier.notify(EntityType.ENTITY, entityName, TDPSPublishStatusType.PUBLISH, Arrays.asList(certificate));
            }
            return certificate;

        } catch (final CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException.getMessage());
            logger.debug(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_ENCODING_FAILED + certificateEncodingException.getMessage());
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException
                | com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException | PersistenceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            logger.debug(ErrorMessages.INTERNAL_ERROR, exception);
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException validationException) {
            logger.error(ErrorMessages.ALGORITHM_NOT_FOUND, validationException.getMessage());
            logger.debug(ErrorMessages.ALGORITHM_NOT_FOUND, validationException);
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND + validationException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            logger.debug(ErrorMessages.ENTITY_NOT_FOUND, entityNotFoundException);
            throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND + entityNotFoundException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException | IOException exception) {
            logger.error(ErrorMessages.CERTIFICATE_GENERATION_FAILED, exception.getMessage());
            logger.debug(ErrorMessages.CERTIFICATE_GENERATION_FAILED, exception);
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_FAILED + exception);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException csrGenerationException) {
            logger.error(ErrorMessages.INVALID_CSR, csrGenerationException.getMessage());
            logger.debug(ErrorMessages.INVALID_CSR, csrGenerationException);
            throw new InvalidCertificateRequestException(ErrorMessages.INVALID_CSR + csrGenerationException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException unsupportedCertificateVersionException) {
            logger.error(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION, unsupportedCertificateVersionException.getMessage());
            logger.debug(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION, unsupportedCertificateVersionException);
            throw new CertificateGenerationException(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION + unsupportedCertificateVersionException);
        } catch (final com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException exception) {
            logger.error(ErrorMessages.ALGORITHM_NOT_FOUND, exception.getMessage());
            logger.debug(ErrorMessages.ALGORITHM_NOT_FOUND, exception);
            systemRecorder.recordSecurityEvent("Entity Certificate Management Service", "EntityCertificateManager", "Algorithm not found to generate certificate for entity " + entityName,
                    "EntityCertificateGenetation", ErrorSeverity.ERROR, "FAILURE");
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND + exception.getMessage());
        }

    }

    /**
     * Generates key pair for the entity and CSR. This CSR passed to PKI Core to generate entity certificate. Generated certificate and private key are stored in key store. The newly generated
     * certificate will automatically be published to TDPS. Key store bytes, alias name of the private key and key store password are formed in model {@link KeyStoreInfo}. This {@link KeyStoreInfo}
     * object is returned.
     *
     * @param entityName
     *            name of the entity.
     * @param password
     *            password to be used for the key store.
     * @param keyStoreType
     *            type of the key store to be formed.
     * @param requestType
     *            type of the certificate request.
     * @return {@link KeyStoreInfo} model which has all the details of the key store generated.
     *
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid entity Attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public KeyStoreInfo generateKeyStore(final String entityName, final char[] password, final KeyStoreType keyStoreType, final RequestType requestType) throws AlgorithmNotFoundException,
            CertificateGenerationException, CertificateRequestGenerationException, CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException,
            InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException, KeyPairGenerationException, RevokedCertificateException {

        if (keyStoreType == null) {
            throw new CertificateGenerationException(ErrorMessages.KEYSTORE_TYPE_NULL);
        }

        final Entity entity = entityHelper.getEntity(entityName);

        final Algorithm keyGenerationAlgorithm = entityHelper.getOverridenKeyGenerationAlgorithm(entity);
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        final CertificateProfile certificateProfile = entity.getEntityProfile().getCertificateProfile();
        final Algorithm signatureAlgorithm = certificateProfile.getSignatureAlgorithm();

        algorithmCompatibilityValidator.checkSignatureAndKeyGenerationAlgorithms(signatureAlgorithm.getName(), keyGenerationAlgorithm.getName());

        final KeyPair keyPair = entityHelper.generateKeyPair(keyGenerationAlgorithm);
        final Certificate certificate = generateCertificatewithoutCSR(entity, keyPair, requestType);
        final X509Certificate certificateChain[] = new X509Certificate[] { certificate.getX509Certificate() };

        final String keyStoreFilePath = keyStoreUtil.createKeyStore(password, keyStoreType, keyPair, certificateChain, entityName);
        final byte[] keyStoreFileData = sdkResourceManagementLocalService.getBytesAndDelete(keyStoreFilePath);

        return keyStoreUtil.buildKeyStoreInfoModel(password, entityName, keyStoreFileData);
    }

    private Certificate generateCertificatewithoutCSR(final Entity entity, final KeyPair keyPair, final RequestType requestType) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateRequestGenerationException, CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidEntityException,
            InvalidEntityAttributeException, RevokedCertificateException {

        try {

            final CertificateRequest certificateRequest = entityHelper.generatePKCS10Request(entity, keyPair);

            if (requestType == RequestType.REKEY) {
                certificateValidator.verifyEntityStatusForReissue(entity);
            }
            certificateValidator.validateIssuerChain(entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName());

            if (entityHelper.isSubjectContainsOverrideOperator(entity)) {
                throw new InvalidEntityException(ErrorMessages.INVALID_ENTITY_SUBJECT);
            }

            if (entityHelper.isSANContainsOverrideOperator(entity)) {
                throw new InvalidEntityException(ErrorMessages.INVALID_ENTITY_SAN);

            }
            // TORF-143242 - Removing DNQ from the Certificate unblock the AMOS issue
            SubjectUtils.removeDNQFromSubject(entity.getEntityInfo().getSubject());
            final CertificateGenerationInfo certificateGenerateInfo = certificateInfoBuilder.build(entity, requestType);
            certificateGenerateInfo.setCertificateRequest(certificateRequest);
            entityCertificatePersistenceHelper.storeCertificateGenerateInfo(certificateGenerateInfo);

            logger.debug("Calling pki core to generate certificate for Entity {}", entity.getEntityInfo().getName());
            final Certificate certificate = certificatemanagementEserviceProxy.getCoreCertificateManagementService().createCertificate(certificateGenerateInfo);
            logger.info("PKI core returned the certificate {}", certificate.getSerialNumber());

            entityCertificatePersistenceHelper.storeCertificate(entity, certificateGenerateInfo, certificate);

            if (entity.isPublishCertificatetoTDPS()) {
                certificateEventNotifier.notify(EntityType.ENTITY, entity.getEntityInfo().getName(), TDPSPublishStatusType.PUBLISH, Arrays.asList(certificate));
            }

            return certificate;

        } catch (final CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException.getMessage());
            logger.debug(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_ENCODING_FAILED + certificateEncodingException.getMessage());
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException
                | com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException | PersistenceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            logger.debug(ErrorMessages.INTERNAL_ERROR, exception);
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException validationException) {
            logger.error(ErrorMessages.ALGORITHM_NOT_FOUND, validationException.getMessage());
            logger.debug(ErrorMessages.ALGORITHM_NOT_FOUND, validationException);
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND + validationException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            logger.debug(ErrorMessages.ENTITY_NOT_FOUND, entityNotFoundException);
            throw new EntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND + entityNotFoundException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException | IOException exception) {
            logger.error(ErrorMessages.CERTIFICATE_GENERATION_FAILED, exception.getMessage());
            logger.debug(ErrorMessages.CERTIFICATE_GENERATION_FAILED, exception);
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_FAILED + exception);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException csrGenerationException) {
            logger.error(ErrorMessages.INVALID_CSR, csrGenerationException.getMessage());
            logger.debug(ErrorMessages.INVALID_CSR, csrGenerationException);
            throw new CertificateGenerationException(ErrorMessages.INVALID_CSR + csrGenerationException);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException unsupportedCertificateVersionException) {
            logger.error(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION, unsupportedCertificateVersionException.getMessage());
            logger.debug(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION, unsupportedCertificateVersionException);
            throw new CertificateGenerationException(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION + unsupportedCertificateVersionException);
        }

    }

    /**
     * Returns a list of certificates issued for Entity based on CertificateStatus.
     *
     * @param entityName
     *            The entity name.
     * @param certificateStatus
     *            The certificate status.
     * @return List of Certificate objects.
     *
     * @throws CertificateNotFoundException
     *             Throws in case of entity does not have certificate.
     * @throws CertificateServiceException
     *             Throws in case of any database errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             Thrown in case of given Entity does not exists.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity is not valid.
     */
    public List<Certificate> listCertificates(final String entityName, final CertificateStatus... certificateStatus) throws CertificateNotFoundException, CertificateServiceException,
            EntityNotFoundException, InvalidEntityAttributeException {
        if (entityHelper.isEntityNameAvailable(entityName)) {
            throw new EntityNotFoundException("Entity not found with Name: " + entityName);
        }

        try {
            final List<Certificate> certificateList = entityCertificatePersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_1, certificateStatus);
            if (certificateList == null) {
                throw new CertificateNotFoundException("No " + Arrays.toString(certificateStatus) + " certificate found");
            }
            return certificateList;
        } catch (final PersistenceException exception) {
            logger.error("Exception while retrieving certificate", exception.getMessage());
            logger.debug("Exception while retrieving certificate", exception);
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        } catch (final CertificateException | IOException certificateException) {
            throw new InvalidEntityAttributeException(ErrorMessages.UNEXPECTED_ERROR + certificateException);
        }
    }

    private void validateCertificateRequest(final CertificateRequest certificateRequest, final Entity entity) throws InvalidCertificateRequestException, CANotFoundException {

        if (certificateRequest == null || (certificateRequest.getCertificateRequestHolder() == null)) {
            logger.error(ErrorMessages.CSR_MANDATORY);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_MANDATORY);
        } else {
            if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
                final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder();
                final PKCS10CertificationRequest certificationRequest = pkcs10CertificationRequestHolder.getCertificateRequest();
                certificateRequestValidator.validate(certificationRequest);
            }

            else {
                final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
                final CertificateRequestMessage certificateRequestMessage = crmfRequestHolder.getCertificateRequest();
                crmfValidator.validate(certificateRequestMessage, entity);
            }
        }
    }

    /**
     *
     * This implementation need to be align with the latest object model and this will be covered in the user story TORF-63444.
     *
     * Return entity's trust CA certificates
     *
     * @param entityName
     *            name of the entity for which trusted certificates are mapped to.
     * @return List of Certificate objects.
     *
     * @throws CertificateServiceException
     *             Throws in case of any database errors or any unconditional exceptions while retrieving the trust profile.
     * @throws EntityNotFoundException
     *             Thrown in case of given Entity does not exists.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidEntityAttributeException
     *             Thrown when the entity has invalid attribute.
     * @throws ProfileNotFoundException
     *             Thrown when there is no trust profile found for a given entity name.
     */

    public List<Certificate> getTrustCertificates(final String entityName, final CertificateStatus... certificateStatuses) throws CertificateServiceException, EntityNotFoundException,
            ExternalCredentialMgmtServiceException, InvalidCAException, InvalidEntityAttributeException, ProfileNotFoundException {

        logger.debug("Retrieving trust certificates for the entity name {}", entityName);
        final Set<Certificate> trustCertificates = new LinkedHashSet<Certificate>();

        final Entity entity = entityHelper.getEntity(entityName);
        final List<TrustProfile> trustProfileList = entity.getEntityProfile().getTrustProfiles();

        if (trustProfileList.isEmpty()) {
            throw new ProfileNotFoundException(ErrorMessages.NO_TRUST_PROFILE_FOUND);
        }

        for (final TrustProfile trustProfile : trustProfileList) {
            trustCertificates.addAll(getInternalCACertificates(trustProfile, certificateStatuses));
            trustCertificates.addAll(getExternalCACertificates(trustProfile));
        }

        logger.info("Retrieved list Of TrustCertificates {}", trustCertificates.size());
        return new ArrayList<Certificate>(trustCertificates);
    }

    /**
     * This method is used to get the Certificates of External CAs which are mentioned in the Trust Profile.
     *
     * @param trustProfile
     *            Trust Profile contains the list of Trusted CA names.
     * @return List of External CA certificates
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown in case of any database errors or any unconditional exceptions.
     */
    public List<Certificate> getExternalCACertificates(final TrustProfile trustProfile) throws ExternalCredentialMgmtServiceException {

        List<Certificate> listOfTrustCertificates = null;
        try {
            final List<ExtCA> trustExternalCAs = trustProfile.getExternalCAs();
            listOfTrustCertificates = new ArrayList<Certificate>();

            for (final ExtCA extCA : trustExternalCAs) {
                final String externalCAName = extCA.getCertificateAuthority().getName();
                listOfTrustCertificates.addAll(caPersistenceHelper.getCertificatesForExtCA(externalCAName, CertificateStatus.ACTIVE));
            }
        } catch (final CertificateException | IOException e) {
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.UNEXPECTED_ERROR, e);
        } catch (final PersistenceException e) {
            throw new ExternalCredentialMgmtServiceException(ErrorMessages.INTERNAL_ERROR, e);
        }

        return listOfTrustCertificates;
    }

    private List<Certificate> getInternalCACertificates(final TrustProfile trustProfile, final CertificateStatus... certificateStatuses) throws CertificateServiceException, InvalidCAException,
            InvalidEntityAttributeException {

        final List<TrustCAChain> trustInternalCAChains = trustProfile.getTrustCAChains();
        final List<Certificate> listOfTrustCertificates = new ArrayList<Certificate>();

        for (final TrustCAChain trustCAChain : trustInternalCAChains) {
            final String internalCAName = trustCAChain.getInternalCA().getCertificateAuthority().getName();
            if (trustCAChain.isChainRequired()) {
                listOfTrustCertificates.addAll(getCertificateChain(internalCAName, certificateStatuses));
            } else {
                final List<Certificate> activeAndInactiveCertificates = getCACertificates(trustCAChain.getInternalCA().getCertificateAuthority(), certificateStatuses);
                if (ValidationUtils.isNullOrEmpty(activeAndInactiveCertificates)) {
                    logger.error("{} doesn't have any valid certificate", internalCAName);
                    throw new InvalidCAException(ErrorMessages.CA_CERTIFICATES_NOT_FOUND);
                }
                listOfTrustCertificates.addAll(activeAndInactiveCertificates);
            }
        }
        return listOfTrustCertificates;
    }

    /**
     * This method is used to publish certificate to TDPS. Also this method dispatches event to Trust Distribution Service.This method is used to update publish flag in DB in case Publish API is being
     * called.
     *
     * @param entityName
     *            Certificate for this entity will be published from Trust distribution service
     *
     * @throws CertificateServiceException
     *             Any internal DB error while retrieving entities.
     * @throws EntityNotFoundException
     *             is thrown in case entity is not found
     */

    public void publishCertificate(final String entityName) throws CertificateServiceException, CANotFoundException, EntityNotFoundException {
        final List<Certificate> certificates = getActiveInActiveCertificates(entityName);

        try {
            if (certificates == null) {
                throw new CertificateServiceException(ErrorMessages.ENTITY_CERTIFICATES_NOT_FOUND);
            }

            tdpsPersistenceHandler.updateEntityData(entityName, EntityType.ENTITY, true);
            certificateEventNotifier.notify(EntityType.ENTITY, entityName, TDPSPublishStatusType.PUBLISH, certificates);
        } catch (final PersistenceException | CertificateEncodingException | EntityServiceException exception) {
            CertificateServiceExceptionUtil.throwCertificateServiceException(exception);
        }
    }

    /**
     * This method is used to un-publish certificate to TDPS. Also this method dispatches event to Trust Distribution Service.This method is used to update publish flag in DB in case Publish API is
     * being called.
     *
     * @param entityName
     *            Certificate for this entity will be un published from Trust distribution service
     *
     * @throws CertificateServiceException
     *             Any internal DB error while retrieving entities.
     *
     * @throws EntityNotFoundException
     *             is thrown in case entity is not found
     */
    public void unPublishCertificate(final String entityName) throws CertificateServiceException, CANotFoundException, EntityNotFoundException {
        final List<Certificate> certificates = getActiveInActiveCertificates(entityName);

        try {
            if (certificates == null) {
                throw new CertificateServiceException(ErrorMessages.ENTITY_CERTIFICATES_NOT_FOUND);
            }

            tdpsPersistenceHandler.updateEntityData(entityName, EntityType.ENTITY, false);
            certificateEventNotifier.notify(EntityType.ENTITY, entityName, TDPSPublishStatusType.UNPUBLISH, certificates);
        } catch (final PersistenceException | CertificateEncodingException | EntityServiceException exception) {
            CertificateServiceExceptionUtil.throwCertificateServiceException(exception);
        }
    }

    private List<Certificate> getActiveInActiveCertificates(final String entityName) throws CertificateServiceException {
        List<Certificate> activeAndInactiveCertificates;

        try {
            activeAndInactiveCertificates = entityCertificatePersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
        } catch (final CertificateException | IOException | PersistenceException exception) {
            throw new CertificateServiceException(exception);
        }

        return activeAndInactiveCertificates;
    }

    /**
     * To get CA certificates for given Certificate Authority
     * 
     * @param certificateAuthority
     *            the Certificate Authority
     * @param certificateStatuses
     *            the Status of Certificates Required
     * @return the List of Certificates
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while fetching certificate.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     */
    public List<Certificate> getCACertificates(final CertificateAuthority certificateAuthority, final CertificateStatus... certificateStatuses) throws CertificateServiceException,
            EntityNotFoundException {
        List<Certificate> activeAndInactiveCertificates;

        try {
            activeAndInactiveCertificates = caPersistenceHelper.getCertificates(certificateAuthority.getName(), MappingDepth.LEVEL_2, certificateStatuses);
            if (certificateAuthority.isRootCA()) {
                final Iterator<Certificate> iterator = activeAndInactiveCertificates.iterator();
                while (iterator.hasNext()) {
                    final Certificate certificate = iterator.next();
                    if (certificate.getStatus() == CertificateStatus.INACTIVE && verifySubCAsRevokedOrExpired(certificate)) {
                        logger.info("INACTIVE root certificate serial number to be removed from trusted certs : {}", certificate.getSerialNumber());
                        iterator.remove();
                    }
                }
            }
        } catch (final CertificateException | IOException | PersistenceException exception) {
            throw new CertificateServiceException(exception);
        }

        return activeAndInactiveCertificates;
    }

    private boolean verifySubCAsRevokedOrExpired(final Certificate issuerCertificate) {

        final List<CertificateData> certificateDatas = caPersistenceHelper.getActiveInActiveCertificateDatas(issuerCertificate);
        if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return true;
        }
        return false;
    }

    /**
     * This method is used to remove duplicate certificates from List of certificates.
     * 
     * @param trustCertificates
     *            List of Certificate objects
     * @return List of unique Certificate objects.
     * 
     */

    public List<Certificate> removeDuplicatesCertificates(final List<Certificate> trustCertificates) {
        final Map<Integer, Certificate> uniqueTrustCertificates = new LinkedHashMap<Integer, Certificate>();
        for (final Certificate certificate : trustCertificates) {
            uniqueTrustCertificates.put(certificate.getX509Certificate().getSerialNumber().hashCode() + certificate.getX509Certificate().getIssuerX500Principal().toString().hashCode(), certificate);
        }
        trustCertificates.clear();
        trustCertificates.addAll(uniqueTrustCertificates.values());

        return trustCertificates;
    }

    /**
     * This method will perform the chain validation for the given entity certificate with the given serial number and issuer name. Returns true if the certificate is a valid. Return false if 1. The
     * entity does not have any certificate. 2. No active certificate found with the given serial number and issuer name. 3. The entity certificate with given serial number and issuer name has an
     * invalid certificate chain. This chain validation ensures that all the certificates in the certificate chain should be in ACTIVE state.
     * 
     * @param entityName
     *            Name of the entity whose certificate need to be validated.
     * @param serialNumber
     *            Serial number of the entity certificate which has to be validated.
     * @param issuerName
     *            Issuer name for the given certificate.
     * @return True if the certificate is valid, false otherwise.
     * @throws CertificateServiceException
     *             Throws in case of any database errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             Thrown in case of given Entity does not exists.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity is not valid.
     */
    public boolean isValidCertificate(final String entityName, final String serialNumber, final String issuerDN) throws CertificateServiceException, EntityNotFoundException,
            InvalidEntityAttributeException {
        logger.info("isValidCertificate method in EntityCertificateManager");
        boolean validCertificate = false;
        String serialNumberToHex = null;
        try {
            final Certificate activeCertificate = listCertificates(entityName, CertificateStatus.ACTIVE).get(0);
            serialNumberToHex = CertificateUtils.convertCertSerialNumberToHex(serialNumber);
            final List<SubjectField> certificateIssuerDn = activeCertificate.getIssuerCertificate().getSubject().getSubjectFields();
            final String[] issuerDn = SubjectUtils.splitDNs(issuerDN);
            if ((serialNumberToHex.equalsIgnoreCase(activeCertificate.getSerialNumber())) && SubjectUtils.compareDN(issuerDn, certificateIssuerDn)) {
                getCertificateChain(entityName, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_NOT_VALID, CertificateStatus.ACTIVE);
                logger.info("Certificate with serial number {}[{}] for the entity {} has valid certificate chain.", serialNumber, serialNumberToHex, entityName);
                validCertificate = true;
            }
        } catch (final CertificateNotFoundException e) {
            logger.error("No active certificate found for the entity {}", entityName);
            logger.debug("No active certificate found for the entity {}", e);
        } catch (final InvalidCAException e) {
            logger.error("Entity {} has invalid certificate chain", entityName);
            logger.debug("Entity {} has invalid certificate chain", e);
        } catch (final InvalidCertificateStatusException e) {
            logger.error("Error while validating the certificate for the entity {} - {}", entityName, e.getMessage());
            logger.debug("Error while validating the certificate for the entity {} - {}", entityName, e);
        }
        logger.info("Returning validCertificate {}", validCertificate);
        return validCertificate;
    }

    /**
     * This method is used to check if the certificate with the given serialNumber having the given subjectDN and issued by the given issuerDN exists in PKI
     *
     * @param subjectDN
     *            SubjectDN with which the certificate to be verified
     * @param serialNumber
     *            serial number in hexadecimal format
     * @param issuerDN
     *            issuerDN with which the certificate to be verified
     * @return true if the certificate is valid, false otherwise
     * @throws CertificateServiceException
     *             Thrown in case of any database errors or any unconditional exceptions
     */
    public boolean isCertificateExist(final String subjectDN, final String serialNumber, final String issuerDN) throws CertificateServiceException {
        logger.debug("checking the certificate with the fields [subjectDN: {}, serialNumber: {}, issuerDN : {}]", subjectDN, serialNumber, issuerDN);

        Boolean isCertificateExist = false;
        final List<Certificate> certificates = listCertificatesBySerialNumber(serialNumber);
        final String[] inputSubjectDn = SubjectUtils.splitDNs(subjectDN);
        final String[] inputIssuerDn = SubjectUtils.splitDNs(issuerDN);
        for (final Certificate certificate : certificates) {
            final List<SubjectField> certificateSubjectDn = certificate.getSubject().getSubjectFields();
            final List<SubjectField> certificateIssuerDn = certificate.getIssuerCertificate().getSubject().getSubjectFields();
            if ((SubjectUtils.compareDN(inputSubjectDn, certificateSubjectDn) && SubjectUtils.compareDN(inputIssuerDn, certificateIssuerDn))) {
                isCertificateExist = true;
                break;
            }
        }
        logger.info("Returning isCertificateExist {} for the certificate with fields [subjectDN: {}, serialNumber: {}, issuerDN : {}]", isCertificateExist, subjectDN, serialNumber, issuerDN);
        return isCertificateExist;
    }

    private List<Certificate> listCertificatesBySerialNumber(final String serialNumber) throws CertificateServiceException {
        try {
            return entityCertificatePersistenceHelper.getCertificatesBySerialNumber(serialNumber);
        } catch (final CertificateException | IOException | PersistenceException exception) {
            logger.error("Exception while retrieving certificate{}", exception.getMessage());
            logger.debug("Exception while retrieving certificate{}", exception);
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        }
    }

}
