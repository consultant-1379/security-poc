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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;

/**
 * This class acts as builder for {@link CertificateAuthoritySetUpData}
 */
public class CertificateAuthoritySetUpData {
    private String name;
    private boolean isRootCA;
    private CAStatus status;
    private Subject subject;
    private SubjectAltName subjectAltName;
    private CertificateAuthority issuer;
    private Certificate activeCertificate;
    private List<Certificate> inActiveCertificates;
    private List<CRLInfo> crls;

    /**
     * 
     * @param name
     * @return
     */
    public CertificateAuthoritySetUpData name(final String name) {
        this.name = name;
        return this;
    }

    /**
     * 
     * @param isRootCA
     * @return
     */
    public CertificateAuthoritySetUpData isRootCA(final boolean isRootCA) {
        this.isRootCA = isRootCA;
        return this;
    }

    /**
     * 
     * @param status
     * @return
     */
    public CertificateAuthoritySetUpData status(final CAStatus status) {
        this.status = status;
        return this;
    }

    /**
     * 
     * @param subject
     * @return
     */
    public CertificateAuthoritySetUpData subject(final Subject subject) {
        this.subject = subject;
        return this;
    }

    /**
     * 
     * @param subjectAltName
     * @return
     */
    public CertificateAuthoritySetUpData subjectAltName(final SubjectAltName subjectAltName) {
        this.subjectAltName = subjectAltName;
        return this;
    }

    /**
     * 
     * @param issuer
     * @return
     */
    public CertificateAuthoritySetUpData issuer(final CertificateAuthority issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * 
     * @param certificate
     * @return
     */
    public CertificateAuthoritySetUpData activeCertificate(final Certificate certificate) {
        this.activeCertificate = certificate;
        return this;
    }

    /**
     * 
     * @param certificates
     * @return
     */
    public CertificateAuthoritySetUpData inActiveCertificates(final List<Certificate> certificates) {
        this.inActiveCertificates = certificates;
        return this;
    }

    /**
     * 
     * @param certificates
     * @return
     */
    public CertificateAuthoritySetUpData crls(final List<CRLInfo> crls) {
        this.crls = crls;
        return this;
    }

    /**
     * Method that returns valid CertificateAuthority
     * 
     * @return CertificateAuthority
     */
    public CertificateAuthority build() {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(name);
        certificateAuthority.setRootCA(isRootCA);
        certificateAuthority.setStatus(status);
        certificateAuthority.setSubject(subject);
        certificateAuthority.setSubjectAltName(subjectAltName);
        certificateAuthority.setIssuer(issuer);
        certificateAuthority.setActiveCertificate(activeCertificate);
        certificateAuthority.setInActiveCertificates(inActiveCertificates);
        certificateAuthority.setCrlInfo(crls);
        return certificateAuthority;
    }
}