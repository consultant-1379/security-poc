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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * This class acts as builder for {@link CertificateChain}
 */
public class CertificateChainBuilder {
	

    private List<Certificate> certificates;

    /**
     * builder method for setting certificates property
     * 
     * @param certificates
     * @return CertificateChainBuilder
     */

    public CertificateChainBuilder certificates(final List<Certificate> certificates) {

        this.certificates = certificates;
        return this;

        
    }

    /**
     * Return fully build CertificateChain Object.
     * 
     * @return CertificateChain CertificateChain Object.
     */
    public CertificateChain build() {

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(certificates);
        return certificateChain;
    }

}
