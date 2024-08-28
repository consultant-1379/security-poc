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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils;

import java.io.IOException;

import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.PKIMessageUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CRMFRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;

/**
 * This class is used to generate CSR from the RequestMessage.
 * 
 * @author tcsramc
 * 
 */
public class CertificateRequestUtility {

    private CertificateRequestUtility() {

    }

    /**
     * This method extracts CSR from the requestMessage.
     * 
     * @param pKIRequestMessage
     *            RequestMessage
     * @return Returns CSR
     * @throws IOException
     *             is thrown if any I/O error occurs.
     */
    public static CertificateRequest generateCSRfromRequestMessage(final RequestMessage pKIRequestMessage) throws IOException {

        final CertReqMsg certReqMsg = PKIMessageUtil.getCertReqMsg(pKIRequestMessage.getPKIMessage());
        final CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage(certReqMsg);
        final CRMFRequestHolder crmfRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        final CertificateRequest csr = new CertificateRequest();
        csr.setCertificateRequestHolder(crmfRequestHolder);
        return csr;

    }

}
