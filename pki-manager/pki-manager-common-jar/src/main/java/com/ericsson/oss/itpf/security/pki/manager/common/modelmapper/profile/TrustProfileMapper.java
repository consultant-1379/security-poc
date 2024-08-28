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

import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AbstractModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to Trust Profile from API Model to JPA Entity and JPA Entity to API Model. While mapping trust profile from API Model to JPA Entity by using internal CA name actual CA Entity
 * will be searched and retrieved from DB and mapped to JPA Entity.
 *
 */
@RequestScoped
@ProfileQualifier(ProfileType.TRUST_PROFILE)
public class TrustProfileMapper extends AbstractModelMapper {

    @Inject
    ExtCAMapper extCAMapper;

    @Inject
    TrustCAChainsMapper trustCAChainMapper;

    private final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";

    /**
     * This method maps the JPA Entity to its corresponding API Model.
     *
     * @param dataModel
     *            Instance of {@link TrustProfileData}
     * @return Instance of {@link TrustProfile}
     */
    @Override
    public <T, E> T toAPIFromModel(final E profileData) {

        final TrustProfileData trustProfileData = (TrustProfileData) profileData;

        logger.debug("Mapping TrustProfileData entity {} to TrustProfile domain model.", trustProfileData);

        final TrustProfile trustProfile = new TrustProfile();

        trustProfile.setId(trustProfileData.getId());
        trustProfile.setName(trustProfileData.getName());
        trustProfile.setProfileValidity(trustProfileData.getProfileValidity());
        trustProfile.setActive(trustProfileData.isActive());
        trustProfile.setModifiable(trustProfileData.isModifiable());
        // TODO: Populate Internal CA Entities Info Also along with names. JIRA
        // Reference: TORF-42813
        trustProfile.setTrustCAChains(trustCAChainToAPIFromModel(trustProfileData));

        logger.debug("Mapped TrustProfile domain model is {}", trustProfile);

        trustProfile.setExternalCAs(extCAToAPIFromModel(trustProfileData));

        return (T) trustProfile;
    }

    private List<TrustCAChain> trustCAChainToAPIFromModel(final TrustProfileData trustProfileData) {
        final List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
        for (final TrustCAChainData trustCAChainData : trustProfileData.getTrustCAChains()) {
            trustCAChains.add((TrustCAChain) trustCAChainMapper.toAPIFromModel(trustCAChainData));
        }

        return trustCAChains;
    }

    private List<ExtCA> extCAToAPIFromModel(final TrustProfileData trustProfileData) {
        final List<ExtCA> externalCAEntities = new ArrayList<ExtCA>();
        if (trustProfileData.getExternalCAs().size() != 0) {
            for (final CAEntityData externalCAData : trustProfileData.getExternalCAs()) {
                externalCAEntities.add((ExtCA) extCAMapper.toAPIFromModel(externalCAData));
            }
        }

        return externalCAEntities;
    }

    /**
     * This method maps the API Model to its corresponding JPA Entity.
     *
     * @param aPIModel
     *            Instance of {@link TrustProfile}
     * @return Instance of {@link TrustProfileData}
     *
     *
     */
    @Override
    public <T, E> E fromAPIToModel(final T profile)  throws ProfileServiceException{

        final TrustProfile trustProfile = (TrustProfile) profile;

        logger.debug("Mapping TrustProfile domain model entity {} to TrustProfileData.", trustProfile);

        final TrustProfileData trustProfileData = new TrustProfileData();

        trustProfileData.setId(trustProfile.getId());
        trustProfileData.setName(trustProfile.getName());
        trustProfileData.setProfileValidity(trustProfile.getProfileValidity());
        trustProfileData.setActive(trustProfile.isActive());
        trustProfileData.setModifiable(trustProfile.isModifiable());
        final Set<TrustCAChainData> trustCAChainDatas = populateTrustCAChains(trustProfile.getTrustCAChains(), trustProfileData);
        final Set<CAEntityData> externalCADataSet = populateExternalCAs(trustProfile.getExternalCAs());

        trustProfileData.setTrustCAChains(trustCAChainDatas);
        trustProfileData.setExternalCAs(externalCADataSet);

        logger.debug("Mapped TrustProfileData is {}", trustProfileData);

        return (E) trustProfileData;
    }

    private Set<TrustCAChainData> populateTrustCAChains(final List<TrustCAChain> trustCAChains, final TrustProfileData trustProfileData) throws ProfileServiceException {
        final Set<TrustCAChainData> trustCAChainDatas = new HashSet<TrustCAChainData>();

        for (final TrustCAChain trustCAChain : trustCAChains) {
            final TrustCAChainData trustCAChainData = (TrustCAChainData) trustCAChainMapper.fromAPIToModel(trustCAChain);
            trustCAChainData.setTrustProfile(trustProfileData);
            trustCAChainDatas.add(trustCAChainData);
        }

        return trustCAChainDatas;
    }

    private Set<CAEntityData> populateExternalCAs(final List<ExtCA> externalCAs) throws ProfileServiceException {

        final List<String> extCANames = new ArrayList<String>();
        for (final ExtCA extCA : externalCAs) {
            extCANames.add(extCA.getCertificateAuthority().getName());
        }

        return createSetCAEntityData(extCANames, true);
    }

    private Set<CAEntityData> createSetCAEntityData(final List<String> cANames, final boolean isExternalCA) throws ProfileServiceException {
        Set<CAEntityData> cAEntityDataSet = new HashSet<CAEntityData>();

        if (cANames.size() != 0) {
            try {
                cAEntityDataSet = new HashSet<CAEntityData>(persistenceManager.findEntityIN(CAEntityData.class, cANames, NAME_PATH_IN_CA));
            } catch (final PersistenceException persistenceException) {
                logger.error("SQL Exception occurred while retrieving CAs in DB {}", persistenceException.getMessage());
                throw new ProfileServiceException("Occured in retrieving CAs", persistenceException);
            }
        }
        final Set<CAEntityData> cAEntityDataSetRet = new HashSet<CAEntityData>();
        for (final CAEntityData ca : cAEntityDataSet) {
            if (ca.isExternalCA() == isExternalCA) {
                cAEntityDataSetRet.add(ca);
            }
        }
        return cAEntityDataSetRet;
    }

}
