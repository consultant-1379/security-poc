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

import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AbstractModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustCAChainData;

public class TrustCAChainsMapper extends AbstractModelMapper {

    private final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";

    /**
     * This method Converts {@link TrustCAChainData} to {@link TrustCAChain}
     * 
     * @param dataModel
     *            Instance of {@link TrustCAChainData}
     * @return Instance of {@link TrustCAChain}
     */
    @Override
    public <T, E> T toAPIFromModel(final E dataModel) {
        final TrustCAChainData trustCAChainData = (TrustCAChainData) dataModel;

        final CAEntity internalCA = internalCAToAPIFromModel(trustCAChainData.getCAEntity());
        final boolean isChainRequired = trustCAChainData.isChainRequired();

        final TrustCAChain trustCAChain = new TrustCAChain();
        trustCAChain.setChainRequired(isChainRequired);
        trustCAChain.setInternalCA(internalCA);

        return (T) trustCAChain;
    }

    /**
     * @param caEntity
     * @return
     */
    private CAEntity internalCAToAPIFromModel(final CAEntityData caEntityData) {
        final CAEntity caEntity = issuerToAPIFromModel(caEntityData);

        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setId(caEntityData.getEntityProfileData().getId());
        entityProfile.setName(caEntityData.getEntityProfileData().getName());

        caEntity.setEntityProfile(entityProfile);

        logger.debug("Mapped CAEntity domain model is {}", caEntity);

        return caEntity;
    }

    /**
     * This method Converts {@link TrustCAChain} to {@link TrustCAChainData}
     * 
     * @param aPIModel
     *            Instance of {@link TrustCAChain}
     * @return Instance of {@link TrustCAChainData}
     * 
     * @throws ProfileServiceException
     *             thrown when any internal Database errors occur.
     */
    @Override
    public <T, E> E fromAPIToModel(final T aPIModel) throws ProfileServiceException {
        final TrustCAChain trustCAChain = (TrustCAChain) aPIModel;
        CAEntityData internalCAData = null;
        final CAEntity internalCA = trustCAChain.getInternalCA();
        final boolean isChainRequired = trustCAChain.isChainRequired();
        try {
            internalCAData = persistenceManager.findEntityByName(CAEntityData.class, internalCA.getCertificateAuthority().getName(), NAME_PATH_IN_CA);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving CAs in DB {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ENTITIES, persistenceException);
        }

        final TrustCAChainData trustCAChainData = new TrustCAChainData();
        trustCAChainData.setChainRequired(isChainRequired);
        trustCAChainData.setCAEntity(internalCAData);

        return (E) trustCAChainData;
    }

}
