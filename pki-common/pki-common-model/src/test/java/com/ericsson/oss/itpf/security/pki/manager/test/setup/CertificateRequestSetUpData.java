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

import java.text.ParseException;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;

/**
 * This class acts as builder for {@link CertificateRequestSetUpData}
 */
public class CertificateRequestSetUpData {
    /**
     * Method that returns valid certificate request
     * 
     * @return CertificateRequest
     */
    public CertificateRequest getCertificateRequestForEqual() throws ParseException {
        final CertificateRequest csr = new CertificateRequest();
        csr.setStatus(CertificateRequestStatus.NEW);
        return csr;
    }

    /**
     * Method that returns different valid CertificateRequest
     * 
     * @return CertificateRequest
     */
    public CertificateRequest getCertificateRequestForNotEqual() throws ParseException {
        final CertificateRequest csr = new CertificateRequest();
        csr.setStatus(CertificateRequestStatus.FAILED);
        return csr;
    }
}
