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

package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to map EntityProfile from JPA Entity to API Model with only required fields used for Import Profiles operation.
 *
 * @author xsusant
 */
public class EntityProfileExportMapper extends EntityProfileMapper {

    @Inject
    CertificateProfileExportMapper certificateProfileExportMapper;

    @Inject
    TrustProfileExportMapper trustProfileExportMapper;

    /**
     * This method maps the JPA Entity to its corresponding API Model.
     *
     * @param dataModel
     *            Instance of {@link EntityProfileData}
     * @return Instance of {@link EntityProfile}
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileAttributeException
     *             Thrown when Invalid parameters are found in the profile data.
     */
    @Override
    public <T, E> T toAPIFromModel(final E profileData) throws CANotFoundException, InvalidProfileAttributeException {

        final EntityProfileData entityProfileData = (EntityProfileData) profileData;

        logger.debug("Mapping EntityProfileData JPA Entity to EntityProfile model.", entityProfileData);

        final EntityProfile entityProfile = new EntityProfile();

        entityProfile.setId(entityProfileData.getId());
        entityProfile.setName(entityProfileData.getName());
        entityProfile.setCertificateProfile(
                (CertificateProfile) certificateProfileExportMapper.toAPIFromModel(entityProfileData.getCertificateProfileData()));
        entityProfile.setProfileValidity(entityProfileData.getProfileValidity());
        entityProfile.setActive(entityProfileData.isActive());
        entityProfile.setCategory(populateEntityCategoryWithoutId(entityProfileData.getEntityCategory()));
        entityProfile.setModifiable(entityProfileData.isModifiable());
        entityProfile.setSubjectUniqueIdentifierValue(entityProfileData.getSubjectUniqueIdentifierValue());

        if (entityProfileData.getExtendedKeyUsageExtension() != null) {
            entityProfile.setExtendedKeyUsageExtension(
                    JsonUtil.getObjectFromJson(ExtendedKeyUsage.class, entityProfileData.getExtendedKeyUsageExtension()));
        }

        if (entityProfileData.getKeyUsageExtension() != null) {
            entityProfile.setKeyUsageExtension(JsonUtil.getObjectFromJson(KeyUsage.class, entityProfileData.getKeyUsageExtension()));
        }

        if (entityProfileData.getKeyGenerationAlgorithm() != null) {
            entityProfile
                    .setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(entityProfileData.getKeyGenerationAlgorithm()));
        }

        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();

        if (entityProfileData.getTrustProfileDatas() != null) {
            for (final TrustProfileData trustProfileData : entityProfileData.getTrustProfileDatas()) {
                trustProfiles.add((TrustProfile) trustProfileExportMapper.toAPIFromModel(trustProfileData));
            }
        }

        entityProfile.setTrustProfiles(trustProfiles);

        if (entityProfileData.getSubjectDN() != null) {
            entityProfile.setSubject(toSubject(entityProfileData.getSubjectDN()));
        }

        if (entityProfileData.getSubjectAltName() != null) {
            entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));
        }

        logger.debug("Mapped EntityProfile is {}", entityProfile);
        return (T) entityProfile;
    }

    private EntityCategory populateEntityCategoryWithoutId(final EntityCategoryData entityCategoryData) {
        final EntityCategory entityCategory = new EntityCategory();

        if (entityCategoryData != null) {
            entityCategory.setName(entityCategoryData.getName());
            entityCategory.setModifiable(entityCategoryData.isModifiable());
        }

        return entityCategory;
    }

}
