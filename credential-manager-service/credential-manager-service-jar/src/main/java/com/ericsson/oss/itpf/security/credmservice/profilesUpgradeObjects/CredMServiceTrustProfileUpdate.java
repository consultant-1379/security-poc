/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.impl.PKIExtCAManagementSolution;
import com.ericsson.oss.itpf.security.credmservice.util.PkiObjectSelector;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public class CredMServiceTrustProfileUpdate {

    private static final String EPPKI_TP = "EPPKI_TP";

    private static final String EPPKI_CA_NAME = PKIExtCAManagementSolution.getExtCAName()[0];

    private static final Logger log = LoggerFactory.getLogger(CredMServiceTrustProfileUpdate.class);

    /**
     * @param xmlTrustProfile
     */

    public static TrustProfile updateCvn_0(final TrustProfile... trustProfiles) {

        final TrustProfile xmlTrustProfile = trustProfiles[0];

        final TrustProfile pkiTrustProfile = (TrustProfile) PkiObjectSelector.getPkiObject(trustProfiles);

        if (pkiTrustProfile == null) {
            return null;
        }

        if (xmlTrustProfile.getName().equals(EPPKI_TP)) {
            log.info("PKIDbConf : specific update for " + EPPKI_TP + " TrustProfile");

            boolean found = false;
            List<ExtCA> extCAList = pkiTrustProfile.getExternalCAs();
            if (extCAList != null) {
                for (final ExtCA extCA : extCAList) {
                    if (extCA.getCertificateAuthority().getName().equals(EPPKI_CA_NAME)) {
                        found = true;
                        return null;
                    }
                }
            } else {
                extCAList = new ArrayList<ExtCA>();
            }
            if (!found) {
                final ExtCA ePPKICA = new ExtCA();
                final CertificateAuthority certificateAuthority = new CertificateAuthority();
                certificateAuthority.setName(EPPKI_CA_NAME);
                ePPKICA.setCertificateAuthority(certificateAuthority);
                extCAList.add(ePPKICA);
                pkiTrustProfile.setExternalCAs(extCAList);
                return pkiTrustProfile;
            }

        }

        return null;

    }

    public static TrustProfile updateCvn_3(final TrustProfile... trustProfiles) {

        final TrustProfile xmlTrustProfile = trustProfiles[0];

        final TrustProfile pkiTrustProfile = (TrustProfile) PkiObjectSelector.getPkiObject(trustProfiles);

        if (pkiTrustProfile == null) {
            return null;
        }

        if (xmlTrustProfile.getName().equals("IPSEC_NE_CHAIN_TP")) {
            log.info("PKIDbConf : specific update for IPSEC_NE_CHAIN_TP TrustProfile");
            final TrustCAChain internalCa = new TrustCAChain();
            final CertificateAuthority certificateAuthority = new CertificateAuthority();
            final CAEntity caentity = new CAEntity();
            internalCa.setInternalCA(caentity);
            internalCa.getInternalCA().setCertificateAuthority(certificateAuthority);

            internalCa.getInternalCA().getCertificateAuthority().setName("NE_IPsec_CA");
            pkiTrustProfile.getTrustCAChains().add(internalCa);

            return pkiTrustProfile;
        }

        if (xmlTrustProfile.getName().equals("OAM_NE_CHAIN_TP")) {
            log.info("PKIDbConf : specific update for OAM_NE_CHAIN_TP TrustProfile");
            final TrustCAChain internalCa = new TrustCAChain();
            final CertificateAuthority certificateAuthority = new CertificateAuthority();
            final CAEntity caentity = new CAEntity();
            internalCa.setInternalCA(caentity);
            internalCa.getInternalCA().setCertificateAuthority(certificateAuthority);

            internalCa.getInternalCA().getCertificateAuthority().setName("NE_OAM_CA");
            pkiTrustProfile.getTrustCAChains().add(internalCa);

            return pkiTrustProfile;
        }

        return null;

    }

}
