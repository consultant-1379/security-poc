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

import java.util.*;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAExportMapper;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class is used to map TrustProfile from JPA Entity to API Model with only required fields used for Import Profiles operation.
 *
 * @author xsusant
 */
public class TrustProfileExportMapper extends TrustProfileMapper {

    @Inject
    TrustCAChainsExportMapper trustCAChainsExportMapper;

    @Inject
    ExtCAExportMapper extCAExportMapper;

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

        trustProfile.setModifiable(trustProfileData.isModifiable());
        // TODO: Populate Internal CA Entities Info Also along with names. JIRA
        // Reference: TORF-42813
        trustProfile.setTrustCAChains(trustCAChainToAPIFromModelData(trustProfileData));

        logger.debug("Mapped TrustProfile domain model is {}", trustProfile);

        trustProfile.setExternalCAs(extCAToAPIFromModelData(trustProfileData));

        return (T) trustProfile;
    }

    private List<TrustCAChain> trustCAChainToAPIFromModelData(final TrustProfileData trustProfileData) {
        final List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
        for (final TrustCAChainData trustCAChainData : trustProfileData.getTrustCAChains()) {
            trustCAChains.add((TrustCAChain) getTrustCAChain(trustCAChainData));
        }

        return trustCAChains;
    }

    private <T, E> T getTrustCAChain(final E dataModel) {
        final TrustCAChainData trustCAChainData = (TrustCAChainData) dataModel;

        final CAEntityData caEntityData = trustCAChainData.getCAEntity();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());

        final CAEntity internalCA = new CAEntity();
        internalCA.setCertificateAuthority(certificateAuthority);

        final boolean isChainRequired = trustCAChainData.isChainRequired();

        final TrustCAChain trustCAChain = new TrustCAChain();
        trustCAChain.setChainRequired(isChainRequired);
        trustCAChain.setInternalCA(internalCA);
        return (T) trustCAChain;
    }

    private List<ExtCA> extCAToAPIFromModelData(final TrustProfileData trustProfileData) {
        final List<ExtCA> externalCAEntities = new ArrayList<ExtCA>();
        if (trustProfileData.getExternalCAs().size() != 0) {
            for (final CAEntityData externalCAData : trustProfileData.getExternalCAs()) {
                externalCAEntities.add((ExtCA) extCAExportMapper.toAPIFromModel(externalCAData));
            }
        }
        return externalCAEntities;
    }

}
