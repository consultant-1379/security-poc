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

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;

/**
 * This class acts as builder for {@link EntityInfoSetUpData}
 */

public class EntityInfoSetUpData {

    private String name;
    private Subject subject;
    private SubjectAltName subjectAltName;
    private CertificateAuthority issuer;
    private EntityStatus entityStatus;
    private int oTPCount;
    private String oTP;
    private Certificate activeCertificate;
    private List<Certificate> inActiveCertificates;

    /**
     * 
     * @param name
     * @return
     */
    public EntityInfoSetUpData name(final String name) {
        this.name = name;
        return this;
    }

    /**
     * 
     * @param subject
     * @return
     */
    public EntityInfoSetUpData subject(final Subject subject) {
        this.subject = subject;
        return this;
    }

    /**
     * 
     * @param subjectAltName
     * @return
     */
    public EntityInfoSetUpData subjectAltName(final SubjectAltName subjectAltName) {
        this.subjectAltName = subjectAltName;
        return this;
    }

    /**
     * 
     * @param issuer
     * @return
     */
    public EntityInfoSetUpData issuer(final CertificateAuthority issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * 
     * @param entityStatus
     * @return
     */
    public EntityInfoSetUpData entityStatus(final EntityStatus entityStatus) {
        this.entityStatus = entityStatus;
        return this;
    }

    /**
     * 
     * @param oTPCount
     * @return
     */
    public EntityInfoSetUpData oTP(final String oTP) {
        this.oTP = oTP;
        return this;
    }

    /**
     * 
     * @param oTPCount
     * @return
     */
    public EntityInfoSetUpData oTPCount(final int oTPCount) {
        this.oTPCount = oTPCount;
        return this;
    }

    /**
     * 
     * @param activeCertificate
     * @return
     */
    public EntityInfoSetUpData activeCertificate(final Certificate activeCertificate) {
        this.activeCertificate = activeCertificate;
        return this;
    }

    /**
     * 
     * @param inActiveCertificates
     * @return
     */
    public EntityInfoSetUpData inActiveCertificates(final List<Certificate> inActiveCertificates) {
        this.inActiveCertificates = inActiveCertificates;
        return this;
    }

    /**
     * Method that returns valid EntityInfo
     * 
     * @return OtherName
     */
    public EntityInfo build() {
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(name);
        entityInfo.setSubject(subject);
        entityInfo.setSubjectAltName(subjectAltName);
        entityInfo.setOTPCount(oTPCount);
        entityInfo.setOTP(oTP);
        entityInfo.setStatus(entityStatus);
        entityInfo.setIssuer(issuer);
        entityInfo.setInActiveCertificates(inActiveCertificates);
        entityInfo.setActiveCertificate(activeCertificate);
        return entityInfo;
    }

}
