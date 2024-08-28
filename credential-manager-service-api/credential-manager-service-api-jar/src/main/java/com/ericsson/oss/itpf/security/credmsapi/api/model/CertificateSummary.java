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
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import java.io.Serializable;

public class CertificateSummary implements Serializable {

    private static long serialVersionUID = -2977412703925832286L;

    private String issuerDN;
    private String subjectDN;
    private String certificateSN;
    private CertificateStatus certificateStatus;

    /**
     * @param issuerDN
     * @param subjectDN
     * @param certificateSN
     * @param certificateStatus
     */
    public CertificateSummary(final String issuerDN, final String subjectDN, final String certificateSN, final CertificateStatus certificateStatus) {
        super();
        this.issuerDN = issuerDN;
        this.subjectDN = subjectDN;
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
     * @return the issuerDN
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * @param issuerDN
     *            the issuerDN to set
     */
    public void setIssuerDN(final String issuerDN) {
        this.issuerDN = issuerDN;
    }

    /**
     * @return the subjectDN
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * @param subjectDN
     *            the subjectDN to set
     */
    public void setSubjectDN(final String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * @return the certificateSN
     */
    public String getCertificateSN() {
        return certificateSN;
    }

    /**
     * @param certificateSN
     *            the certificateSN to set
     */
    public void setCertificateSN(final String certificateSN) {
        this.certificateSN = certificateSN;
    }

    /**
     * @return the certificateStatus
     */
    public CertificateStatus getCertificateStatus() {
        return certificateStatus;
    }

    /**
     * @param certificateStatus
     *            the certificateStatus to set
     */
    public void setCertificateStatus(final CertificateStatus certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

}
