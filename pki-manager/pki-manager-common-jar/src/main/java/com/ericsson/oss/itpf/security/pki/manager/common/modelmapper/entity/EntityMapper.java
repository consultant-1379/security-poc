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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity;

import java.util.*;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.*;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RequestScoped
@EntityQualifier(EntityType.ENTITY)
public class EntityMapper extends AbstractModelMapper {

    @Inject
    @ProfileQualifier(ProfileType.ENTITY_PROFILE)
    EntityProfileMapper entityProfileMapper;

    @Inject
    EntityCategoryMapper entityCategoryMapper;

    @Inject
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @Inject
    EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    /**
     * Maps the Entity JPA model to its corresponding API model. This method also maps the active and inactive certificates of the entity.
     *
     * @param entityData
     *            EntityData Object which should be converted to API model Entity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T, E> T toAPIFromModel(final E dataModel) throws InvalidEntityAttributeException {

        final EntityData entityData = (EntityData) dataModel;

        logger.debug("Mapping EntityData entity to Entity domain model for {}", entityData.getEntityInfoData().getName());

        final Entity entity = toAPIFromModelWithoutCertificates(dataModel);
        final EntityInfo entityInfo = entity.getEntityInfo();

        final EntityInfoData entityInfoData = entityData.getEntityInfoData();

        final List<CertificateData> certificateDatas = entityCertificatePersistenceHelper.getCertificateDatas(entityInfoData.getName(),
                CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
        if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {
            final List<Certificate> inActiveCertificates = new ArrayList<Certificate>();
            for (final CertificateData certificateData : certificateDatas) {
                if (certificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {
                    entityInfo.setActiveCertificate(toObjectModelWithOutChain(certificateData));
                } else if (certificateData.getStatus().intValue() == CertificateStatus.INACTIVE.getId()) {
                    inActiveCertificates.add(toObjectModelWithOutChain(certificateData));
                }
            }
            entityInfo.setInActiveCertificates(inActiveCertificates);
        }

        entity.setEntityInfo(entityInfo);
        final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet = entityData
                .getCertificateExpiryNotificationDetailsData();
        entity.setCertificateExpiryNotificationDetails(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet));
        return (T) entity;
    }

    /**
     * Maps the Entity JPA model to its corresponding API model. This method maps the name, the subject and the status of the entity.
     *
     * @param entityDataList
     *            EntityData Object which should be converted to API model Entity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @SuppressWarnings("unchecked")
    public <T, E> List<T> toAPIModelListForEntitySummary(final List<E> entityDataList) {
        final List<Entity> aPIModelList = new ArrayList<Entity>();

        for (final E entityData : entityDataList) {
            try {
                final Entity aPIModel = toAPIFromModelForSummary(entityData);
                aPIModelList.add(aPIModel);
            } catch (final InvalidEntityAttributeException ex) {
                logger.debug("Invalid Attributes Entity", ex);
            }
        }
        return (List<T>) aPIModelList;
    }

    /**
     * Maps the Entity API model to its corresponding JPA model
     *
     * @param entityData
     *            Entity Object which should be converted to JPA model EntityData
     *
     * @return Returns the JPA model of the given API model
     *
     * @throws EntityServiceException
     *             thrown when any internal Database errors occur.
     *
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T, E> E fromAPIToModel(final T APIModel) throws EntityServiceException {

        final Entity entity = (Entity) APIModel;
        logger.debug("Mapping Entity domain model to EntityData entity for {}", entity);
        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();

        final EntityInfo entityInfo = entity.getEntityInfo();
        EntityProfileData entityProfileData = null;
        try {
            entityProfileData = persistenceManager.findEntityByName(EntityProfileData.class, entity.getEntityProfile().getName(), "name");
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Entity profile from DB {}", persistenceException.getMessage());
            throw new EntityServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILE, persistenceException);
        }
        entityData.setEntityProfileData(entityProfileData);
        entityData.setId(entityInfo.getId());
        entityData.setNameAlias(entityInfo.getName().toLowerCase());
        entityData.setOtpValidityPeriod(entity.getOtpValidityPeriod());
        entityData.setSubjectUniqueIdentifierValue(entity.getSubjectUniqueIdentifierValue());
        entityInfoData.setName(entityInfo.getName());
        entityInfoData.setOtp(entityInfo.getOTP());
        entityInfoData.setOtpCount(entityInfo.getOTPCount());
        entityInfoData.setSubjectDN(SubjectUtils.orderSubjectDN(fromSubject(entityInfo.getSubject())));
        entityInfoData.setSubjectAltName(fromSubjectAltName(entityInfo.getSubjectAltName()));
        entityInfoData.setStatus(entityInfo.getStatus());


        if (entity.getCategory() != null) {
            entityData.setEntityCategoryData(populateEntityCategoryData(entity.getCategory()));
        }
        entityInfoData.setIssuer(entityProfileData.getCertificateProfileData().getIssuerData());

        entityData.setEntityInfoData(entityInfoData);
        entityData.setPublishCertificatetoTDPS(entity.isPublishCertificatetoTDPS());

        try {
            if (entity.getKeyGenerationAlgorithm() != null) {
                entityData.setKeyGenerationAlgorithm(populateKeyGenerationAlgorithm(entity.getKeyGenerationAlgorithm().getName(),
                        entity.getKeyGenerationAlgorithm().getKeySize()));

            }
        } catch (final PKIConfigurationServiceException e) {
            logger.error("SQL Exception occurred while mapping CA Entity API model to JPA model {}", e.getMessage());
            throw new EntityServiceException("Occured in mapping CA Entity ", e);
        }

        final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = entity.getCertificateExpiryNotificationDetails();
        if (!ValidationUtils.isNullOrEmpty(certificateExpiryNotificationDetails)) {
            entityData.setCertificateExpiryNotificationDetailsData(certExpiryNotificationDetailsMapper
                    .fromAPIToModel(certificateExpiryNotificationDetails, Constants.ENTITY_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE));
        }
        logger.debug("Mapped EntityData entity for {}", entityData.getEntityInfoData().getName());
        return (E) entityData;
    }

    /**
     * @param entityCategory
     * @return
     */
    private EntityCategoryData populateEntityCategoryData(final EntityCategory entityCategory) throws EntityServiceException {
        EntityCategoryData entityCategoryData = null;
        try {
            entityCategoryData = persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), "name");
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Entity Category from DB {}", persistenceException.getMessage());
            throw new EntityServiceException("Internal Service Exception while retrieving Entity category", persistenceException);
        }

        return entityCategoryData;
    }

    /**
     *
     * Maps the Entity JPA model to its corresponding API model. This method does not map the active and inactive certificates of the entity.
     *
     * @param entityData
     *            EntityData Object which should be converted to API model Entity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     */
    @SuppressWarnings("unchecked")
    public <T, E> T toAPIFromModelWithoutCertificates(final E dataModel) throws CANotFoundException, InvalidProfileAttributeException {

        final EntityData entityData = (EntityData) dataModel;

        logger.debug("Mapping EntityData entity to Entity domain model for {}", entityData.getEntityInfoData().getName());

        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();

        final EntityInfoData entityInfoData = entityData.getEntityInfoData();
        entity.setOtpValidityPeriod(entityData.getOtpValidityPeriod());
        entityInfo.setId(entityData.getId());
        entityInfo.setName(entityInfoData.getName());
        entityInfo.setStatus(entityInfoData.getStatus());
        entityInfo.setSubject(toSubject(entityInfoData.getSubjectDN()));
        entityInfo.setSubjectAltName(toSubjectAltName(entityInfoData.getSubjectAltName()));

        if (entityData.getEntityCategoryData() != null) {
            entity.setCategory(entityCategoryMapper.toAPIFromModel(entityData.getEntityCategoryData()));
        }

        entityInfo.setOTPCount(entityData.getEntityInfoData().getOtpCount());
        entityInfo.setOTP(entityData.getEntityInfoData().getOtp());
        entityInfo.setIssuer(toCertAuthAPIModelWithoutIssuer(entityData.getEntityInfoData().getIssuer()));
        entity.setEntityInfo(entityInfo);
        entity.setPublishCertificatetoTDPS(entityData.isPublishCertificatetoTDPS());

        if (entityData.getKeyGenerationAlgorithm() != null) {
            entity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(entityData.getKeyGenerationAlgorithm()));
        }

        entity.setSubjectUniqueIdentifierValue(entityData.getSubjectUniqueIdentifierValue());
        entity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(entityData.getEntityProfileData()));

        entity.setPublishCertificatetoTDPS(entityData.isPublishCertificatetoTDPS());

        logger.debug("Mapped Entity domain model for {}", entity.getEntityInfo().getName());

        return (T) entity;

    }

    /**
     * Maps the Entity JPA model to its corresponding API model. This method maps the name, subject and status of the entity.
     *
     * @param dataModel
     *            EntityData Object which should be converted to API model Entity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @SuppressWarnings("unchecked")
    public <T, E> T toAPIFromModelForSummary(final E dataModel) throws InvalidEntityAttributeException {

        final EntityData entityData = (EntityData) dataModel;

        logger.debug("Mapping EntityData entity to Entity domain model for {}", entityData.getEntityInfoData().getName());

        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();

        final EntityInfoData entityInfoData = entityData.getEntityInfoData();

        entityInfo.setId(entityData.getId());
        entityInfo.setName(entityInfoData.getName());
        entityInfo.setStatus(entityInfoData.getStatus());
        entityInfo.setSubject(toSubject(entityInfoData.getSubjectDN()));
        entity.setSubjectUniqueIdentifierValue(entityData.getSubjectUniqueIdentifierValue());
        entity.setEntityInfo(entityInfo);

        return (T) entity;
    }

}