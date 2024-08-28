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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import java.util.*;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AbstractModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to map Entity Profile from API Model to JPA Entity and JPA Entity to API Model. While mapping entity profile from API Model to JPA Entity by using keyGenerationAlgorithm name
 * actual KeyGenerationAlgorithm will be searched and retrieved from DB and mapped to JPA Entity
 *
 */
@RequestScoped
@ProfileQualifier(ProfileType.ENTITY_PROFILE)
public class EntityProfileMapper extends AbstractModelMapper {

    @Inject
    @ProfileQualifier(ProfileType.CERTIFICATE_PROFILE)
    CertificateProfileMapper certificateProfileMapper;

    @Inject
    @ProfileQualifier(ProfileType.TRUST_PROFILE)
    TrustProfileMapper trustProfileMapper;

    private final static String NAME_PATH = "name";

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
     *
     */
    @Override
    public <T, E> T toAPIFromModel(final E profileData) throws CANotFoundException, InvalidProfileAttributeException {

        final EntityProfileData entityProfileData = (EntityProfileData) profileData;

        logger.debug("Mapping EntityProfileData JPA Entity to EntityProfile model.", entityProfileData);

        final EntityProfile entityProfile = new EntityProfile();

        entityProfile.setId(entityProfileData.getId());
        entityProfile.setName(entityProfileData.getName());
        entityProfile.setCertificateProfile((CertificateProfile) certificateProfileMapper.toAPIFromModel(entityProfileData.getCertificateProfileData()));
        entityProfile.setProfileValidity(entityProfileData.getProfileValidity());
        entityProfile.setActive(entityProfileData.isActive());
        entityProfile.setCategory(populateEntityCategory(entityProfileData.getEntityCategory()));
        entityProfile.setModifiable(entityProfileData.isModifiable());
        entityProfile.setSubjectUniqueIdentifierValue(entityProfileData.getSubjectUniqueIdentifierValue());
        if (entityProfileData.getExtendedKeyUsageExtension() != null) {
            entityProfile.setExtendedKeyUsageExtension(JsonUtil.getObjectFromJson(ExtendedKeyUsage.class, entityProfileData.getExtendedKeyUsageExtension()));
        }

        if (entityProfileData.getKeyUsageExtension() != null) {
            entityProfile.setKeyUsageExtension(JsonUtil.getObjectFromJson(KeyUsage.class, entityProfileData.getKeyUsageExtension()));
        }

        if (entityProfileData.getKeyGenerationAlgorithm() != null) {
            entityProfile.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(entityProfileData.getKeyGenerationAlgorithm()));
        }

        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();

        if (entityProfileData.getTrustProfileDatas() != null) {
            for (final TrustProfileData trustProfileData : entityProfileData.getTrustProfileDatas()) {
                trustProfiles.add((TrustProfile) trustProfileMapper.toAPIFromModel(trustProfileData));
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

    /**
     * This method maps the API Model to its corresponding JPA Entity.
     *
     * @param aPIModel
     *            Instance of {@link EntityProfile}
     * @return Instance of {@link EntityProfileData}
     */
    @Override
    public <T, E> E fromAPIToModel(final T profile) throws  ProfileServiceException  {

        final EntityProfile entityProfile = (EntityProfile) profile;

        logger.debug("Mapping CertificateProfile domain model entity {} to CertificateProfileData.", entityProfile);

        final EntityProfileData entityProfileData = new EntityProfileData();

        entityProfileData.setId(entityProfile.getId());
        entityProfileData.setName(entityProfile.getName());
        entityProfileData.setProfileValidity(entityProfile.getProfileValidity());
        entityProfileData.setActive(entityProfile.isActive());
        entityProfileData.setSubjectUniqueIdentifierValue(entityProfile.getSubjectUniqueIdentifierValue());

        if (entityProfile.getCategory() != null && entityProfile.getCategory().getName() != null) {
            final String entityCategoryName = entityProfile.getCategory().getName();

            entityProfileData.setEntityCategory(populateEntityCategoryData(entityCategoryName));
        }

        entityProfileData.setModifiable(entityProfile.isModifiable());

        if (entityProfile.getSubject() != null) {
            entityProfileData.setSubjectDN(fromSubject(entityProfile.getSubject()));
        }

        if (entityProfile.getSubjectAltNameExtension() != null) {
            entityProfileData.setSubjectAltName(JsonUtil.getJsonFromObject(entityProfile.getSubjectAltNameExtension(), false));
        }

        if (entityProfile.getExtendedKeyUsageExtension() != null) {
            entityProfileData.setExtendedKeyUsageExtension(JsonUtil.getJsonFromObject(entityProfile.getExtendedKeyUsageExtension(), false));
        }

        if (entityProfile.getKeyUsageExtension() != null) {
            entityProfileData.setKeyUsageExtension(JsonUtil.getJsonFromObject(entityProfile.getKeyUsageExtension(), false));
        }

        final String certificateProfileName = entityProfile.getCertificateProfile().getName();
        try {
            entityProfileData.setCertificateProfileData(persistenceManager.findEntityByName(CertificateProfileData.class, certificateProfileName, NAME_PATH));
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving certificate profile{} ", certificateProfileName, " in DB {}", e.getMessage());
            throw new ProfileServiceException("Occured in retrieving certificate profile", e);
        }

        final Set<TrustProfileData> trustProfileDatas = new HashSet<TrustProfileData>();


        if (entityProfile.getTrustProfiles() != null) {
            for (final TrustProfile trustProfile : entityProfile.getTrustProfiles()) {
                try {
                    trustProfileDatas.add(persistenceManager.findEntityByName(TrustProfileData.class, trustProfile.getName(), NAME_PATH));
                } catch (final PersistenceException e) {
                    logger.error("SQL Exception occurred while retrieving trustProfile{} ",  trustProfile.getName()+ " in DB {}", e.getMessage());
                    throw new ProfileServiceException("Occured in retrieving trustProfile", e);
                }
            }
        }


        entityProfileData.setTrustProfileDatas(trustProfileDatas);
        try {
            if (entityProfile.getKeyGenerationAlgorithm() != null) {
                entityProfileData
                        .setKeyGenerationAlgorithm(populateKeyGenerationAlgorithm(entityProfile.getKeyGenerationAlgorithm().getName(), entityProfile.getKeyGenerationAlgorithm().getKeySize()));
            }
        } catch (PKIConfigurationServiceException e) {
            logger.error("SQL Exception occurred while mapping Entity Profile API model to JPA model {}", e.getMessage());
            throw new EntityServiceException("Occured in mapping Entity Profile ", e);
        }

        logger.debug("Mapped EntityProfileData is {}", entityProfileData);
        return (E) entityProfileData;
    }

    /**
     * @param entityCategoryData
     * @return
     */
    private EntityCategory populateEntityCategory(final EntityCategoryData entityCategoryData) {
        final EntityCategory entityCategory = new EntityCategory();

        if (entityCategoryData != null) {
            entityCategory.setId(entityCategoryData.getId());
            entityCategory.setName(entityCategoryData.getName());
            entityCategory.setModifiable(entityCategoryData.isModifiable());
        }

        return entityCategory;
    }

    /**
     * @param entityCategory
     * @return
     */
    private EntityCategoryData populateEntityCategoryData(final String entityCategoryName) throws ProfileServiceException {
        EntityCategoryData entityCategoryData = new EntityCategoryData();
        try {
            entityCategoryData = persistenceManager.findEntityByName(EntityCategoryData.class, entityCategoryName, NAME_PATH);
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving entity category{} ", entityCategoryName, " in DB {}", e.getMessage());
            throw new ProfileServiceException("Occured in retrieving entity category", e);
        }
        return entityCategoryData;
    }
}