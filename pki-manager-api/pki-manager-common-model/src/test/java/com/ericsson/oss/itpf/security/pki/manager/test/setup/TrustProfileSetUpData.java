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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;

import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public class TrustProfileSetUpData {

    private final TrustCAChainSetupData trustCAChainSetupData;
    private final CertificateAuthoritySetUpData certificateAuthoritySetUpData;

    private static final String EQUAL_TP_NAME = "TrustProfileEqual";
    private static final String NOT_EQUAL_TP_NAME = "TrustProfileNotEqual";

    private static final String CA_NAME_1 = "CA 1";
    private static final String CA_NAME_2 = "CA 2";
    private static final String CA_NAME_3 = "CA 3";
    private static final String CA_NAME_4 = "CA 4";

    /**
	 * 
	 */
    public TrustProfileSetUpData() {
        trustCAChainSetupData = new TrustCAChainSetupData();
        certificateAuthoritySetUpData = new CertificateAuthoritySetUpData();
    }

    /**
     * Method that returns valid TrustProfile
     * 
     * @return TrustProfile
     * @throws DatatypeConfigurationException
     */
    public TrustProfile getTrustProfileDataForEqual() throws DatatypeConfigurationException {
        final TrustProfile trustProfile = new TrustProfile();
        final List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
        final TrustCAChain trustCAChain1 = trustCAChainSetupData.getTrustCAChainForEqual();
        final TrustCAChain trustCAChain2 = trustCAChainSetupData.getTrustCAChainForEqual();
        changeCANameInTrustCAChain(trustCAChain1, CA_NAME_1);
        changeCANameInTrustCAChain(trustCAChain2, CA_NAME_2);
        trustCAChains.add(trustCAChain1);
        trustCAChains.add(trustCAChain2);
        trustProfile.setTrustCAChains(trustCAChains);
        trustProfile.setActive(true);
        trustProfile.setName(EQUAL_TP_NAME);
        trustProfile.setProfileValidity(new Date(1437726693));
        return trustProfile;
    }

    /**
     * Method that returns different TrustProfile object
     * 
     * @return TrustProfile
     * @throws DatatypeConfigurationException
     */
    public TrustProfile getTrustProfileDataForNotEqual() throws DatatypeConfigurationException {
        final TrustProfile trustProfile = new TrustProfile();
        final List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
        final TrustCAChain trustCAChain1 = trustCAChainSetupData.getTrustCAChainForNotEqual();
        final TrustCAChain trustCAChain2 = trustCAChainSetupData.getTrustCAChainForNotEqual();
        changeCANameInTrustCAChain(trustCAChain1, CA_NAME_3);
        changeCANameInTrustCAChain(trustCAChain2, CA_NAME_4);
        trustCAChains.add(trustCAChain1);
        trustCAChains.add(trustCAChain2);
        trustProfile.setTrustCAChains(trustCAChains);
        trustProfile.setActive(false);
        trustProfile.setName(NOT_EQUAL_TP_NAME);
        trustProfile.setProfileValidity(new Date());
        return trustProfile;
    }

    private void changeCANameInTrustCAChain(final TrustCAChain trustCAChain, final String name) {
        trustCAChain.getInternalCA().setCertificateAuthority(certificateAuthoritySetUpData.name(name).build());
    }
}
