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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

/**
 * Class for Test Data creation for {@link TrustProfile}
 * 
 * @version 1.2.4
 */
public class TrustProfileSetUpToTest {

    private TrustProfile trustProfile;

    /**
     * Method to provide dummy data for tests.
     */
    public TrustProfileSetUpToTest() {
        fillTrustProfile();
    }

    /**
     * Method to fill dummy data into TrustProfile.
     */
    private void fillTrustProfile() {

        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
        final TrustCAChain trustCAChain = new TrustCAChain();

        certificateAuthority.setId(1);
        certificateAuthority.setName("Internal CA 1");
        caEntity.setCertificateAuthority(certificateAuthority);

        trustCAChain.setInternalCA(caEntity);
        trustCAChain.setChainRequired(true);

        trustCAChains.add(trustCAChain);

        trustProfile = new TrustProfile();

        trustProfile.setId(1);
        trustProfile.setName("TestProfile");
        trustProfile.setActive(true);
        trustProfile.setModifiable(true);

        trustProfile.setTrustCAChains(trustCAChains);

    }

    /**
     * @return the trustProfile
     */
    public TrustProfile getTrustProfile() {
        return trustProfile;
    }

}
