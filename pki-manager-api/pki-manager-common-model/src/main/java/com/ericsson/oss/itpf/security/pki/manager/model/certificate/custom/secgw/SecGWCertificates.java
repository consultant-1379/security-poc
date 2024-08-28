/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.manager.model.certificate.custom.secgw;

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * Contains certificates and trusted certificates for SecGW.
 *
 * @author xlakdag
 */
public class SecGWCertificates implements Serializable {

    private static final long serialVersionUID = 3880550507938279050L;
    private Certificate certificate;
    private CertificateChain certificateChain;
    private List<Certificate> trustedCertificates;

    /**
     * To get the certificate of secgw
     * @return the certificate
     */
    public Certificate getCertificate() {
        return certificate;
    }

    /**
     * To set the certificate of secgw
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * To get the secgw certificate chain
     * @return the certificateChain
     */
    public CertificateChain getCertificateChain() {
        return certificateChain;
    }

    /**
     * To set the certificate chain of secgw
     * @param certificateChain
     *            the certificateChain to set
     */
    public void setCertificateChain(CertificateChain certificateChain) {
        this.certificateChain = certificateChain;
    }

    /**
     * To get the Trusted certificates
     * @return the trustedCertificates
     */
    public List<Certificate> getTrustedCertificates() {
        return trustedCertificates;
    }

    /**
     * To set the trusted certificates
     * @param trustedCertificates
     *            the trustedCertificates to set
     */
    public void setTrustedCertificates(List<Certificate> trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
    }

    @Override
    public String toString() {
        return "SecGWCertificates [certificate=" + certificate + ", certificateChain=" + certificateChain + ", trustedCertificates="
                + trustedCertificates + "]";
    }
}
