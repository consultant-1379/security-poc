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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.certificatemanagement.builder.CSRBuilder;
import com.ericsson.oss.itpf.security.pki.common.certificatemanagement.generator.KeyPairGenerator;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.override.SubAltNameOverrider;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.override.SubjectOverrider;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class EntityHelper {

    @Inject
    Logger logger;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityPersistenceHandler<CAEntity> cAEntityPersistenceHandler;

    @Inject
    @EntityQualifier(EntityType.ENTITY)
    EntityPersistenceHandler<Entity> entityPersistenceHandler;

    @Inject
    CSRBuilder cSRBuilder;

    @Inject
    KeyPairGenerator keyPairGenerator;

    @Inject
    SubjectOverrider subjectOverrider;

    @Inject
    SubAltNameOverrider subAltNameOverrider;

    /**
     * Generates Certificate Signing Request for Entity.
     *
     * @param entity
     *            The entity object.
     * @param keyPair
     *            {@link KeyPair} for the corresponding entity
     * @return CertificateRequest return {@link CertificateRequest}
     * @throws CertificateRequestGenerationException
     *             Thrown in case of any failures generating the CSR.
     */

    public CertificateRequest generatePKCS10Request(final Entity entity, final KeyPair keyPair) throws CertificateRequestGenerationException {

        final String signatureAlgorithm = entity.getEntityProfile().getCertificateProfile().getSignatureAlgorithm().getName();
        final String subjectDN = entity.getEntityInfo().getSubject().toASN1String();
        final CertificateRequest certificateRequest = new CertificateRequest();

        try {
            final PKCS10CertificationRequest pkcs10CertificationRequest = cSRBuilder.generatePKCS10Request(new X500Name(subjectDN), keyPair, signatureAlgorithm, null);

            final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
            certificateRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);
            return certificateRequest;

        } catch (final IOException ioException) {
            logger.error(ErrorMessages.CSR_ENCODING_FAILED, ioException);
            throw new CertificateRequestGenerationException(ErrorMessages.CSR_ENCODING_FAILED);
        } catch (final InvalidKeyException invalidKeyException) {
            logger.error(ErrorMessages.CSR_KEY_INVALID, invalidKeyException);
            throw new CertificateRequestGenerationException(ErrorMessages.CSR_KEY_INVALID);
        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
            throw new CertificateRequestGenerationException(ErrorMessages.ALGORITHM_IS_NOT_FOUND);
        } catch (final SignatureException signatureException) {
            logger.error(ErrorMessages.CSR_SIGNATURE_GENERATION_FAILED, signatureException);
            throw new CertificateRequestGenerationException(ErrorMessages.CSR_SIGNATURE_GENERATION_FAILED);
        }

    }

    /**
     * Generates KeyPair using keyGenerationAlgorithm.
     *
     * @param keyGenerationAlgorithm
     *            The algorithm for generating keys.
     * @return KeyPair generated {@link KeyPair} object
     *
     * @throws KeyPairGenerationException
     *             Thrown when there is an error in key pair generation.
     */
    public KeyPair generateKeyPair(final Algorithm keyGenerationAlgorithm) throws KeyPairGenerationException {

        try {
            validateECDSAKeyGenAlgorithm(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());
            String keyGenerationAlgorithmName = keyGenerationAlgorithm.getName();
            keyGenerationAlgorithmName = keyGenerationAlgorithmName.equals(Constants.ECDSA_ALGORITHM_NAME) ? Constants.EC_ALGORITHM_NAME : keyGenerationAlgorithmName;

            return keyPairGenerator.generateKeyPair(keyGenerationAlgorithmName, keyGenerationAlgorithm.getKeySize());

        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
            throw new KeyPairGenerationException(ErrorMessages.ALGORITHM_IS_NOT_FOUND + noSuchAlgorithmException);
        }

    }

    /**
     * Validates ECDSA weak and not supported algorithms.
     *
     * @param keyGenerationAlgorithmName
     *            Key Generation Algorithm Name.
     * @param keySize
     *            Key Size of Algorithm.
     * @throws KeyPairGenerationException
     *             Thrown incase weak/not supported ECDSA algorithm for key pair
     */
    public void validateECDSAKeyGenAlgorithm(final String keyGenerationAlgorithmName, final Integer keySize) throws KeyPairGenerationException {

        if (keyGenerationAlgorithmName.equals(Constants.ECDSA_ALGORITHM_NAME) && !(keySize.equals(256) || keySize.equals(384) || keySize.equals(521))) {
            final String errorMessage = ErrorMessages.ECDSA_KEY_SIZE_NOT_SUPPORTED + keySize;
            logger.error(errorMessage);
            throw new KeyPairGenerationException(errorMessage);
        }
    }

    // TODO : This method will move to common pki-manager common
    /**
     * Method for retrieving an entity based on name.
     *
     * @param entityName
     * @return instance of {@link Entity} found in DB.
     *
     * @throws CertificateServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws EntityNotFoundException
     *             Thrown when entity do not exists in DB.
     * @throws InvalidEntityAttributeException
     *             thrown when Entity Attribute is Invalid.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     */
    public Entity getEntity(final String entityName) throws CertificateServiceException, EntityNotFoundException, InvalidEntityAttributeException , InvalidProfileAttributeException{

        Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entity.setEntityInfo(entityInfo);
        try {
            entity = entityPersistenceHandler.getEntityForCertificateGeneration(entity);
        } catch (final EntityServiceException entityServiceException) {
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, entityServiceException);
        }
        logger.debug("Retrieved Entity {}  ", entity);
        return entity;
    }

    /**
     * Gets the {@link CAEntity} from the entity management service.
     *
     * @param caEntityName
     *            name of the CA Entity.
     * @return {@link CAEntity} model.
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurs while getting the CA Entity.
     * @throws InvalidCAException
     *             Thrown in case given ca not found in the database.
     * @throws InvalidEntityAttributeException
     *             Thrown in case of entity has invalid attribute.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     */
    public CAEntity getCAEntity(final String caEntityName) throws CertificateServiceException, CANotFoundException, InvalidEntityAttributeException, InvalidProfileAttributeException {

        CAEntity caEntity = new CAEntity();

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(caEntityName);
        caEntity.setCertificateAuthority(certificateAuthority);

        try {
            caEntity = cAEntityPersistenceHandler.getEntityForCertificateGeneration(caEntity);
        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND, entityNotFoundException);
        } catch (final EntityServiceException entityServiceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, entityServiceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, entityServiceException);
        }

        return caEntity;
    }

    /**
     * This service will return entity key generation Algorithm if CertificateRequest key generation algorithm matches with entity key generation algorithm. Otherwise this will check csr key
     * generation algorithm with profile key generation algorithm.If matches, return profile key generation algorithm.
     *
     * @param entity
     *            The entity Object.
     * @param csrKeyGenerationAlgorihm
     *            KeyGenerationAlgorihm which is present in the CSR.
     * @throws InvalidCertificateRequestException
     *             Thrown in case CSR keyGeneration Algorithm is not matched with entity keyGenerationAlgorithm if exists, or if it is not matched with entity profile or certificate profile
     *             keyGenerationAlgorithm.
     */
    public Algorithm validateAndGetAlgorithmModel(final Entity entity, final String csrKeyGenerationAlgorihm) throws InvalidCertificateRequestException {

        final Algorithm entityKeyGenerationAlgorithm = entity.getKeyGenerationAlgorithm();

        if (entityKeyGenerationAlgorithm != null) {

            if (csrKeyGenerationAlgorihm.equals(entityKeyGenerationAlgorithm.getName())) {
                return entityKeyGenerationAlgorithm;
            } else {
                logger.error(ErrorMessages.INVALID_KEY_GENERATION_ALGORTITHM);
                throw new InvalidCertificateRequestException(ErrorMessages.INVALID_KEY_GENERATION_ALGORTITHM);
            }
        }

        final Algorithm entityProfileKeyGenerationAlgorithm = entity.getEntityProfile().getKeyGenerationAlgorithm();
        if (entityProfileKeyGenerationAlgorithm != null) {
            if (csrKeyGenerationAlgorihm.equals(entityProfileKeyGenerationAlgorithm.getName())) {
                return entityProfileKeyGenerationAlgorithm;
            } else {
                logger.error(ErrorMessages.INVALID_KEY_GENERATION_ALGORTITHM);
                throw new InvalidCertificateRequestException(ErrorMessages.INVALID_KEY_GENERATION_ALGORTITHM);
            }
        }

        final List<Algorithm> certificateProfileKeyGenerationAlgorithm = entity.getEntityProfile().getCertificateProfile().getKeyGenerationAlgorithms();

        if (!certificateProfileKeyGenerationAlgorithm.isEmpty()) {
            for (final Algorithm algorithm : certificateProfileKeyGenerationAlgorithm) {

                if (csrKeyGenerationAlgorihm.equals(algorithm.getName())) {
                    return algorithm;
                } else {
                    logger.error(ErrorMessages.INVALID_KEY_GENERATION_ALGORTITHM);
                    throw new InvalidCertificateRequestException(ErrorMessages.INVALID_KEY_GENERATION_ALGORTITHM);
                }
            }

        }
        return null;
    }

    /**
     * Check to override entity SAN fields with CertificateRequest subjectAltName fields.
     *
     * @param certificateRequest
     *            CertificateRequest Object.
     * @param entity
     *            The entity object.
     */
    public void setEntitySubject(final CertificateRequest certificateRequest, final Entity entity) {

        if (isSubjectContainsOverrideOperator(entity)) {
            final Subject entitySubject = subjectOverrider.overrideSubject(entity.getEntityInfo().getSubject(), certificateRequest);
            entity.getEntityInfo().setSubject(entitySubject);
            logger.debug("Overridden entity subject fields {} ", entity.getEntityInfo().getSubject());
        }
    }

    /**
     * Check to override entity subject fields with CertificateRequest subjectAltName fields.
     *
     * @param certificateRequest
     *            CertificateRequest Object.
     * @param entity
     *            The entity object.
     */
    public void setEntitySubjectAltName(final CertificateRequest certificateRequest, final Entity entity) {

        if (isSANContainsOverrideOperator(entity)) {
            final SubjectAltName entitySubjectAltName = subAltNameOverrider.overrideSubjectAltName(entity.getEntityInfo().getSubjectAltName(), certificateRequest);
            entity.getEntityInfo().setSubjectAltName(entitySubjectAltName);
            logger.debug("Overridden entity subjectAltName fields {} ", entity.getEntityInfo().getSubjectAltName());
        }
    }

    /**
     * Check entity subject fields contains override operator.
     *
     * @param entity
     *            The entity Object.
     * @return true if entity subject fields contains override operator.
     *
     */
    public boolean isSubjectContainsOverrideOperator(final Entity entity) {

        final Subject subject = entity.getEntityInfo().getSubject();

        if (subject != null) {

            for (final SubjectField subjectField : subject.getSubjectFields()) {

                if (subjectField.getValue().equals(Constants.OVERRIDE_OPERATOR)) {
                    return true;
                }

            }

        }

        return false;

    }

    /**
     * Check entity subjectAltName fields contains override operator.
     *
     * @param entity
     *            The entity Object.
     * @return true if entity subjectAltName fields contains override operator.
     */

    public boolean isSANContainsOverrideOperator(final Entity entity) {

        final SubjectAltName entitySubjectAltName = entity.getEntityInfo().getSubjectAltName();

        if (entitySubjectAltName == null) {
            return false;

        }

        for (final SubjectAltNameField subjectAltNameField : entitySubjectAltName.getSubjectAltNameFields()) {
            switch (subjectAltNameField.getType()) {
            case EDI_PARTY_NAME:
                final EdiPartyName ediPartyName = new EdiPartyName();
                ediPartyName.setNameAssigner(Constants.OVERRIDE_OPERATOR);
                ediPartyName.setPartyName(Constants.OVERRIDE_OPERATOR);
                if (subjectAltNameField.getValue().equals(ediPartyName)) {
                    return true;
                }
                break;
            case OTHER_NAME:
                final OtherName otherName = new OtherName();
                otherName.setTypeId(Constants.OVERRIDE_OPERATOR);
                otherName.setValue(Constants.OVERRIDE_OPERATOR);
                if (subjectAltNameField.getValue().equals(otherName)) {
                    return true;
                }
                break;
            default:
                final SubjectAltNameString stringValue = new SubjectAltNameString();
                stringValue.setValue(Constants.OVERRIDE_OPERATOR);
                if (subjectAltNameField.getValue().equals(stringValue)) {
                    return true;
                }
            }
            subjectAltNameField.getValue();
        }
        return false;

    }

    /**
     * Gets overriden key generation algorithm from the CA Entity. It gets the key generation algorithm if exists in {@link CAEntity} model otherwise it gets from {@link EntityProfile} of that CA
     * Entity otherwise it gets from {@link CertificateProfile} of CA Entity.
     *
     * @param abstractEntity
     *            {@link AbstractEntity} model.
     * @throws InvalidCAException
     *             Thrown when {@link CertificateProfile} of CA has multiple key generation algorithms if algorithm needs to be taken from profile.
     */
    public Algorithm getOverridenKeyGenerationAlgorithm(final AbstractEntity abstractEntity) throws InvalidCAException {

        Algorithm entityKeyGenerationAlgorithm = null;

        if (abstractEntity instanceof CAEntity) {
            final CAEntity caEntity = (CAEntity) abstractEntity;
            entityKeyGenerationAlgorithm = caEntity.getKeyGenerationAlgorithm();
        } else {
            final Entity entity = (Entity) abstractEntity;
            entityKeyGenerationAlgorithm = entity.getKeyGenerationAlgorithm();
        }

        if (entityKeyGenerationAlgorithm != null) {
            return entityKeyGenerationAlgorithm;
        }

        final Algorithm entityProfileKeyGenerationAlgorithm = abstractEntity.getEntityProfile().getKeyGenerationAlgorithm();

        if (entityProfileKeyGenerationAlgorithm != null) {
            return entityProfileKeyGenerationAlgorithm;
        }

        final List<Algorithm> certificateProfileKeyGenerationAlgorithm = abstractEntity.getEntityProfile().getCertificateProfile().getKeyGenerationAlgorithms();

        if (certificateProfileKeyGenerationAlgorithm.size() > 1) {
            throw new InvalidCAException(ErrorMessages.MULTIPLE_KEY_GENERATION_ALGORTITHM);
        }
        return certificateProfileKeyGenerationAlgorithm.get(0);
    }

    /**
     * This method is used check the availability of Name used for {@link Entity}
     *
     * @param name
     *            name of entity to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     *
     */
    public boolean isEntityNameAvailable(final String name) throws EntityServiceException {

        return entityPersistenceHandler.isNameAvailable(name);
    }

    /**
     * This method is used check the availability of Name used for {@link CAEntity}
     *
     * @param name
     *            name of entity to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws InternalServiceException
     *             Thrown when any internal error occurs in system.
     *
     */

    public boolean isCAEntityNameAvailable(final String name) throws EntityServiceException {

        return cAEntityPersistenceHandler.isNameAvailable(name);
    }


    /**
     * Gets overriden subject unique identifier value from the Entity.
     *
     * @param abstractEntity
     *            {@link AbstractEntity} model.
     * @return subject unique identifier value
     */
    public String getOverridenSubjectUniqueIdentifierValue(final AbstractEntity abstractEntity) {

        String subjectUniqueIdentifierValue = null;

        final Entity entity = (Entity) abstractEntity;
        subjectUniqueIdentifierValue = entity.getSubjectUniqueIdentifierValue();

        if (subjectUniqueIdentifierValue != null) {
            return subjectUniqueIdentifierValue;
        }

        final String entityProfileSubjectUniqueIdentifier = abstractEntity.getEntityProfile().getSubjectUniqueIdentifierValue();

        if (entityProfileSubjectUniqueIdentifier != null) {
            return entityProfileSubjectUniqueIdentifier;
        }
        return Constants.DEFAULT_SUBJECT_UNIQUE_IDENTIFIER_VALUE;
    }

}