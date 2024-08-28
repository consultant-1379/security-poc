/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Set;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to map Entity from JPA Entity to API Model with only required fields used for Import entities operation.
 *
 * @author xsusant
 */
public class EntityExportMapper extends EntityMapper {


    /**
     * Maps the Entity JPA model to its corresponding API model. This method also maps the active and inactive certificates of the entity.
     *
     * @param entityData
     *            EntityData Object which should be converted to API model Entity
     * @return Returns the API model of the given JPA model
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T, E> T toAPIFromModel(final E dataModel) throws InvalidEntityAttributeException {

        final EntityData entityData = (EntityData) dataModel;

        logger.debug("Mapping EntityData entity to Entity domain model for {}", entityData.getEntityInfoData().getName());

        final Entity entity = getEntityFromModel(dataModel);
        final EntityInfo entityInfo = entity.getEntityInfo();

        entity.setEntityInfo(entityInfo);
        final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet = entityData
                .getCertificateExpiryNotificationDetailsData();
        entity.setCertificateExpiryNotificationDetails(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet));

        return (T) entity;
    }

    private <T, E> T getEntityFromModel(final E dataModel) throws CANotFoundException, InvalidProfileAttributeException {

        final EntityData entityData = (EntityData) dataModel;

        logger.debug("Mapping EntityData entity to Entity domain model for {}", entityData.getEntityInfoData().getName());

        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        final EntityInfoData entityInfoData = entityData.getEntityInfoData();

        entity.setOtpValidityPeriod(entityData.getOtpValidityPeriod());

        entityInfo.setId(entityData.getId());
        entityInfo.setName(entityInfoData.getName());
        entityInfo.setSubject(toSubject(entityInfoData.getSubjectDN()));
        entityInfo.setSubjectAltName(toSubjectAltName(entityInfoData.getSubjectAltName()));
        entityInfo.setStatus(entityInfoData.getStatus());

        if (entityData.getEntityCategoryData() != null) {
            entity.setCategory(entityCategoryMapper.toAPIFromModel(entityData.getEntityCategoryData()));
        }

        entityInfo.setOTP(entityData.getEntityInfoData().getOtp());
        entityInfo.setOTPCount(entityData.getEntityInfoData().getOtpCount());
        entityInfo.setIssuer(getCertificateAuthorityFromModel(entityData.getEntityInfoData().getIssuer()));
        entity.setEntityInfo(entityInfo);
        entity.setPublishCertificatetoTDPS(entityData.isPublishCertificatetoTDPS());

        if (entityData.getKeyGenerationAlgorithm() != null) {
            entity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmDataForImport(entityData.getKeyGenerationAlgorithm()));
        }

        final EntityProfileData entityProfileData = entityData.getEntityProfileData();
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setActive(entityProfileData.isActive());
        entityProfile.setModifiable(entityProfileData.isModifiable());
        entityProfile.setName(entityProfileData.getName());
        entityProfile.setId(entityProfileData.getId());
        entity.setSubjectUniqueIdentifierValue(entityData.getSubjectUniqueIdentifierValue());
        entity.setEntityProfile(entityProfile);
        entity.setPublishCertificatetoTDPS(entityData.isPublishCertificatetoTDPS());
        logger.debug("Mapped Entity domain model for {}", entity.getEntityInfo().getName());
        return (T) entity;
    }

    private CertificateAuthority getCertificateAuthorityFromModel(final CAEntityData caEntityData) {
        if (caEntityData == null) {
            return null;
        }

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());
        certificateAuthority.setSubject(toSubject(certificateAuthorityData.getSubjectDN()));
        certificateAuthority.setSubjectAltName(toSubjectAltName(certificateAuthorityData.getSubjectAltName()));
        certificateAuthority.setRootCA(certificateAuthorityData.isRootCA());
        certificateAuthority.setStatus(CAStatus.getStatus(certificateAuthorityData.getStatus()));
        certificateAuthority.setPublishToCDPS(certificateAuthorityData.isPublishToCDPS());
        certificateAuthority.setIssuerExternalCA(certificateAuthorityData.isIssuerExternalCA());
        try {
            certificateAuthority
                    .setCrlGenerationInfo(cRLGenerationInfoMapper.toAPIFromModelForImport(certificateAuthorityData.getCrlGenerationInfo()));
        } catch (final InvalidCRLGenerationInfoException | CertificateException | IOException e) {
            logger.error(ErrorMessages.INVALID_CRL_GENERATION_INFO_FOR_CA + certificateAuthorityData.getName());
            logger.debug(ErrorMessages.INVALID_CRL_GENERATION_INFO_FOR_CA + certificateAuthorityData.getName(), e);
        }

        return certificateAuthority;
    }

}
