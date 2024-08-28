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
package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

/**
 * This class contains the data specific to CAEntity. The parameters which are common to both the caentity and entity are extended from EntityDetails
 * abstract class.
 *
 * @author tcssote
 */
public class CaEntityDetails extends AbstractEntityDetails {
    CertificateAuthority certificateAuthority;

    public CaEntityDetails(final boolean publishCertificatetoTDPS, final EntityProfile entityProfile, final Algorithm keyGenerationAlgorithm,
                           final EntityType type, final CertificateAuthority certificateAuthority) {
        super(publishCertificatetoTDPS, entityProfile, keyGenerationAlgorithm, type);
        this.certificateAuthority = certificateAuthority;
    }

    /**
     * @return the certificateAuthority
     */
    public CertificateAuthority getCertificateAuthority() {
        return certificateAuthority;
    }

    /**
     * @param certificateAuthority
     *            the certificateAuthority to set
     */
    public void setCertificateAuthority(final CertificateAuthority certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
    }
}
