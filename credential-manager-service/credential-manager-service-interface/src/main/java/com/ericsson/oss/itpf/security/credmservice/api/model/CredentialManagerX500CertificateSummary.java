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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

public class CredentialManagerX500CertificateSummary implements Serializable {

    private static final long serialVersionUID = -944162616814194557L;

    private X500Principal subjectX500Principal;
    private X500Principal issuerX500Principal;
    private BigInteger certificateSN;
    private CredentialManagerCertificateStatus certificateStatus;

    /**
     * 
     */
    public CredentialManagerX500CertificateSummary() {
        super();
    }

    /**
     * @param subjectX500Principal
     * @param issuerX500Principal
     * @param certificateSN
     * @param certificateStatus
     */
    public CredentialManagerX500CertificateSummary(X500Principal subjectX500Principal, X500Principal issuerX500Principal, BigInteger certificateSN, CredentialManagerCertificateStatus certificateStatus) {
        super();
        this.subjectX500Principal = subjectX500Principal;
        this.issuerX500Principal = issuerX500Principal;
        this.certificateSN = certificateSN;
        this.certificateStatus = certificateStatus;
    }

    /**
     * @return the serialversionuid
     */
    public static long getSerialversionuid() {
        return serialVersionUID;
    }

    /**
     * @return the subjectX500Principal
     */
    public X500Principal getSubjectX500Principal() {
        return subjectX500Principal;
    }

    /**
     * @param subjectX500Principal
     *            the subjectX500Principal to set
     */
    public void setSubjectX500Principal(final X500Principal subjectX500Principal) {
        this.subjectX500Principal = subjectX500Principal;
    }

    /**
     * @return the issuerX500Principal
     */
    public X500Principal getIssuerX500Principal() {
        return issuerX500Principal;
    }

    /**
     * @param issuerX500Principal
     *            the issuerX500Principal to set
     */
    public void setIssuerX500Principal(final X500Principal issuerX500Principal) {
        this.issuerX500Principal = issuerX500Principal;
    }

    /**
     * @return the certificateSN
     */
    public BigInteger getCertificateSN() {
        return certificateSN;
    }

    /**
     * @param certificateSN
     *            the certificateSN to set
     */
    public void setCertificateSN(final BigInteger certificateSN) {
        this.certificateSN = certificateSN;
    }

    /**
     * @return the certificateStatus
     */
    public CredentialManagerCertificateStatus getCertificateStatus() {
        return certificateStatus;
    }

    /**
     * @param certificateStatus
     *            the certificateStatus to set
     */
    public void setCertificateStatus(final CredentialManagerCertificateStatus certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

}
