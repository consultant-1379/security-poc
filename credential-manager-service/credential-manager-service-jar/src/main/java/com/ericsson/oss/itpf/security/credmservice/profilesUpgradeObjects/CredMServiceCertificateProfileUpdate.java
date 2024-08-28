/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.util.PkiObjectSelector;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

public class CredMServiceCertificateProfileUpdate {

    private static final Logger log = LoggerFactory.getLogger(CredMServiceCertificateProfileUpdate.class);

    public static CertificateProfile updateCvn_0(final CertificateProfile... certificateProfiles) {

        final CertificateProfile xmlCertificateProfile = certificateProfiles[0];
        final CertificateProfile pkiCertificateProfile = (CertificateProfile) PkiObjectSelector.getPkiObject(certificateProfiles);

        if (pkiCertificateProfile == null) {
            return null;
        }

        log.info("updateCvn_0 : CertificateProfile = " + pkiCertificateProfile.getName() + " ... Updating from xml stuff");
        xmlCertificateProfile.setId(pkiCertificateProfile.getId());
        return xmlCertificateProfile;
    }

    @java.lang.SuppressWarnings("squid:S2189")
    public static CertificateProfile updateCvn_1(final CertificateProfile... certificateProfiles) {

        final CertificateProfile xmlCertificateProfile = certificateProfiles[0];

        final CertificateProfile pkiCertificateProfile = (CertificateProfile) PkiObjectSelector.getPkiObject(certificateProfiles);

        final CertificateExtensions certificateExtensions = xmlCertificateProfile.getCertificateExtensions();

        if (certificateExtensions != null) {
            int size = certificateExtensions.getCertificateExtensions().size();

            for (final int i = 0; i < size; size++) {
                if (certificateExtensions.getCertificateExtensions().get(i) instanceof CRLDistributionPoints) {
                    xmlCertificateProfile.setId(pkiCertificateProfile.getId());
                    log.info(
                            "updateCvn_1 : CertificateProfile = " + pkiCertificateProfile.getName() + " ... Updating from xml stuff size is:" + size);
                    return xmlCertificateProfile;
                }
            }
        }

        if (PkiObjectSelector.checkObjectAllocation(certificateProfiles)) {
            log.debug("updateCvn_1 : CertificateProfile updated before for {}", pkiCertificateProfile.getName());
            return pkiCertificateProfile;
        } else {
            log.debug("updateCvn_1 : CertificateProfile not needed for {}", pkiCertificateProfile.getName());
            return null;
        }

    }

}
