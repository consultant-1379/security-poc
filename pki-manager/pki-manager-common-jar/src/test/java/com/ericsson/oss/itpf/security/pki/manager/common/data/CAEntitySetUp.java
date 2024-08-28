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
package com.ericsson.oss.itpf.security.pki.manager.common.data;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * This class populates dummy data for {@link CAEntity} related models
 * 
 * @author xnagcho
 * @version 1.1.30
 * 
 */
public class CAEntitySetUp {

    /**
     * Method that returns CertificateAuthority with given name
     * 
     * @param name
     *            name of the CAEntity
     * @return CertificateAuthority Instance of {@link CertificateAuthority} with name set.
     */
    public CertificateAuthority getCertificateAuthority(final String name) {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(name);
        // certificateAuthority.setPublishCertificateToTDPS(true);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.ACTIVE);

        return certificateAuthority;
    }

    /**
     * Method that returns CAEntity with given name
     * 
     * @param name
     *            name of the CAEntity
     * @return CAEntity Instance {@link CAEntity} with given name set.
     */
    public CAEntity getCAEntity(final String name) {
        final CAEntity caEntity = new CAEntity();
        //caEntity.setStatus(EntityStatus.NEW);
        caEntity.setType(EntityType.CA_ENTITY);
        //caEntity.setIsCSRGenerated(true);
        caEntity.setCertificateAuthority(getCertificateAuthority(name));

        return caEntity;
    }
}
