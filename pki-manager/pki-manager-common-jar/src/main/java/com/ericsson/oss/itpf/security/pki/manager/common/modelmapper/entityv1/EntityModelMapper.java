/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityCategoryMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.AbstractModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
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
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

@RequestScoped
@EntityQualifier(EntityType.ENTITY)
public class EntityModelMapper extends AbstractModelMapperv1 {

    @Inject
    @ProfileQualifier(ProfileType.ENTITY_PROFILE)
    protected EntityProfileMapper entityProfileMapper;

    @Inject
    protected CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @Inject
    protected EntityCertificatePersistenceHelper entityCertificatePersistenceHelper;

    @Inject
    protected EntityCategoryMapper entityCategoryMapper;

    /**
     * Maps the Entity JPA model to its corresponding API model. This method also maps the active and inactive certificates of the entity.
     *
     * @param EntityData
     *            EntityData Object which should be converted to API model Entity
     *
     * @param MappingDepth
     *            The depth of modeled objects
     * @return Returns the API model of the given JPA model
     *
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @Override
    public <T, E> T toApi(final E dataModel, final MappingDepth depth) throws InvalidEntityAttributeException {

        final EntityData entityData = (EntityData) dataModel;

        logger.debug("Mapping EntityData entity to Entity domain model for {} based on depth {}", entityData.getEntityInfoData().getName(), depth);

        switch (depth) {
        case LEVEL_0:
            return getEntitySummary(entityData);
        case LEVEL_1:
            return prepareEntityWithEmbeddedObjects(dataModel, MappingDepth.LEVEL_1);
        case LEVEL_2:
            return prepareEntityWithEmbeddedObjects(dataModel, MappingDepth.LEVEL_2);
        default:
            logger.debug("Unknown mapping depth");
            return null;
        }
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
    @Override
    public <T, E> E fromApi(final T apiModel) throws EntityServiceException {

        final Entity entity = (Entity) apiModel;
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
                entityData.setKeyGenerationAlgorithm(populateKeyGenerationAlgorithm(entity.getKeyGenerationAlgorithm().getName(), entity
                        .getKeyGenerationAlgorithm().getKeySize()));

            }
        } catch (final PKIConfigurationServiceException e) {
            logger.error("SQL Exception occurred while mapping CA Entity API model to JPA model {}", e.getMessage());
            throw new EntityServiceException("Occured in mapping CA Entity ", e);
        }

        final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = entity.getCertificateExpiryNotificationDetails();
        if (!ValidationUtils.isNullOrEmpty(certificateExpiryNotificationDetails)) {
            entityData.setCertificateExpiryNotificationDetailsData(certExpiryNotificationDetailsMapper.fromAPIToModel(
                    certificateExpiryNotificationDetails, Constants.ENTITY_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE));
        }
        logger.debug("Mapped EntityData entity for {}", entityData.getEntityInfoData().getName());
        return (E) entityData;

    }

    /**
     * Maps the Entity JPA model to its corresponding API model. This method maps the name, subject and status of the entity.
     *
     * @param EntityData
     *            EntityData Object which should be converted to API model Entity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    private <T> T getEntitySummary(final EntityData entityData) throws InvalidEntityAttributeException {

        logger.debug("Mapping EntityData entity to Entity domain model for {}", entityData.getEntityInfoData().getName());

        final Entity entity = new Entity();
        final EntityInfoData entityInfoData = entityData.getEntityInfoData();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setId(entityData.getId());
        entityInfo.setName(entityInfoData.getName());
        entityInfo.setStatus(entityInfoData.getStatus());
        entityInfo.setSubject(toSubject(entityInfoData.getSubjectDN()));
        entityInfo.setSubjectAltName(toSubjectAltName(entityInfoData.getSubjectAltName()));

        entityInfo.setOTPCount(entityData.getEntityInfoData().getOtpCount());
        entityInfo.setOTP(entityData.getEntityInfoData().getOtp());
        entity.setOtpValidityPeriod(entityData.getOtpValidityPeriod());
        entity.setEntityInfo(entityInfo);
        entity.setSubjectUniqueIdentifierValue(entityData.getSubjectUniqueIdentifierValue());
        entity.setPublishCertificatetoTDPS(entityData.isPublishCertificatetoTDPS());
        return (T) entity;
    }

    @Override
    public <T> T getEntitySummaryWithCertificates(final EntityData entityData) throws InvalidEntityAttributeException {
        logger.info("Mapping EntityData entity with certificates to Entity domain model for {}", entityData.getEntityInfoData().getName());
        final Entity entity = new Entity();
        final EntityInfoData entityInfoData = entityData.getEntityInfoData();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setId(entityData.getId());
        entityInfo.setName(entityInfoData.getName());
        entityInfo.setStatus(entityInfoData.getStatus());
        entityInfo.setSubject(toSubject(entityInfoData.getSubjectDN()));
        entityInfo.setSubjectAltName(toSubjectAltName(entityInfoData.getSubjectAltName()));

        entityInfo.setOTPCount(entityData.getEntityInfoData().getOtpCount());
        entityInfo.setOTP(entityData.getEntityInfoData().getOtp());
        entity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(entityData.getEntityProfileData()));
        entity.setOtpValidityPeriod(entityData.getOtpValidityPeriod());
        entity.setEntityInfo(entityInfo);
        entity.setSubjectUniqueIdentifierValue(entityData.getSubjectUniqueIdentifierValue());
        entity.setPublishCertificatetoTDPS(entityData.isPublishCertificatetoTDPS());
        final Set<CertificateData> allCertificates = entityInfoData.getCertificateDatas();
        final List<Certificate> inActiveCertificates = new ArrayList<>();
        for (final CertificateData certificateData : allCertificates) {
            if (certificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {
                entityInfo.setActiveCertificate(getCertificateSummary(certificateData));
            } else if (certificateData.getStatus().intValue() == CertificateStatus.INACTIVE.getId()) {
                inActiveCertificates.add(getCertificateSummary(certificateData));
            }
        }
        entityInfo.setInActiveCertificates(inActiveCertificates);
        return (T) entity;
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
    private <T, E> T prepareEntityWithEmbeddedObjects(final E dataModel, final MappingDepth mappingDepth) throws CANotFoundException,
    InvalidProfileAttributeException {

        final EntityData entityData = (EntityData) dataModel;
        final EntityInfoData entityInfoData = entityData.getEntityInfoData();

        final Entity entity = getEntitySummary(entityData);
        final EntityInfo entityInfo = entity.getEntityInfo();
        if (entityData.getEntityCategoryData() != null) {
            entity.setCategory(entityCategoryMapper.toAPIFromModel(entityData.getEntityCategoryData()));
        }

        entityInfo.setIssuer(getCASummary(entityData.getEntityInfoData().getIssuer()));
        loadActiveAndInactiveCerts(entityInfo, entityInfoData, mappingDepth);
        entity.setEntityInfo(entityInfo);
        entity.setPublishCertificatetoTDPS(entityData.isPublishCertificatetoTDPS());

        if (entityData.getKeyGenerationAlgorithm() != null) {
            entity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(entityData.getKeyGenerationAlgorithm()));
        }
        entity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(entityData.getEntityProfileData()));
        final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet = entityData
                .getCertificateExpiryNotificationDetailsData();
        entity.setCertificateExpiryNotificationDetails(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet));
        entity.setSubjectUniqueIdentifierValue(entityData.getSubjectUniqueIdentifierValue());
        logger.debug("Mapped Entity domain model for {}", entity.getEntityInfo().getName());

        return (T) entity;
    }

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
     * @param entityInfo
     * @param entityInfoData
     * @param mappingDepth
     */
    private void loadActiveAndInactiveCerts(final EntityInfo entityInfo, final EntityInfoData entityInfoData, final MappingDepth mappingDepth) {
        final List<CertificateData> certificateDatas = entityCertificatePersistenceHelper.getCertificateDatas(entityInfoData.getName(),
                CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
        if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {
            final List<Certificate> inActiveCertificates = new ArrayList<>();
            for (final CertificateData certificateData : certificateDatas) {
                if (certificateData.getStatus().intValue() == CertificateStatus.ACTIVE.getId()) {
                    entityInfo.setActiveCertificate(toApi(certificateData, mappingDepth));
                } else if (certificateData.getStatus().intValue() == CertificateStatus.INACTIVE.getId()) {
                    inActiveCertificates.add(toApi(certificateData, mappingDepth));
                }
            }
            entityInfo.setInActiveCertificates(inActiveCertificates);
        }
    }

}
