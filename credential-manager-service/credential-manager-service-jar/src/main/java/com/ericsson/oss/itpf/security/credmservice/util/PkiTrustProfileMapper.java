/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.util;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlTrustProfile;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public final class PkiTrustProfileMapper {

    private PkiTrustProfileMapper() {
    }

    public static TrustProfile ConvertTrustProfileFrom(final XmlTrustProfile xmlTrustProfile) throws PkiProfileMapperException {

        final TrustProfile pkiTrustProfile = new TrustProfile();

        if (xmlTrustProfile == null) {
            throw new PkiProfileMapperException("Input parameter is NULL");
        }

        if (xmlTrustProfile.getExternalCA() != null) {
            final List<ExtCA> extCAs = new ArrayList<ExtCA>();
            for (final String extCAName : xmlTrustProfile.getExternalCA()) {
                final ExtCA extCA = new ExtCA();
                final CertificateAuthority certificateAuthority = new CertificateAuthority();
                certificateAuthority.setName(extCAName);
                extCA.setCertificateAuthority(certificateAuthority);
                extCAs.add(extCA);
            }
            pkiTrustProfile.setExternalCAs(extCAs);
        }

        if (xmlTrustProfile.getInternalCA() != null) {
            final List<TrustCAChain> intCAs = new ArrayList<TrustCAChain>();
        	
            for (final String intCAname : xmlTrustProfile.getInternalCA()){
            	final TrustCAChain intCA = new TrustCAChain();
            	final CertificateAuthority certificateAuthority = new CertificateAuthority();
        		final CAEntity caentity = new CAEntity();
            	intCA.setInternalCA(caentity);
            	intCA.getInternalCA().setCertificateAuthority(certificateAuthority);
            	intCA.getInternalCA().getCertificateAuthority().setName(intCAname);
            	intCAs.add(intCA);
            }

            pkiTrustProfile.setTrustCAChains(intCAs);
        }

        pkiTrustProfile.setName(xmlTrustProfile.getName());
        pkiTrustProfile.setType(ProfileType.TRUST_PROFILE);

        return pkiTrustProfile;
    }
}
