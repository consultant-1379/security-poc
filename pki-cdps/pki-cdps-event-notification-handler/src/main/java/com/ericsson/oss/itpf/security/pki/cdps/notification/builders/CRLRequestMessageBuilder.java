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
package com.ericsson.oss.itpf.security.pki.cdps.notification.builders;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;

/**
 * This Class prepares the CRL RequestMessage Builder using list of CACertificateInfo
 * 
 * @author xjagcho
 *
 */
public class CRLRequestMessageBuilder {
    private List<CACertificateInfo> caCertificateInfos;

    /**
     * This method sets list caCertificateInfos
     * 
     * @param caCertificateInfos
     *            it contains list of CACertificateInfo and it holds caName and serialNumber
     * @return CRLRequestMessageBuilder
     */
    public CRLRequestMessageBuilder caCertificateInfos(final List<CACertificateInfo> caCertificateInfos) {
        this.caCertificateInfos = caCertificateInfos;
        return this;
    }

    /**
     * This method builds the crlRequestMessage using list caCertificateInfos
     * 
     * @return CRLRequestMessage it holds list caCertificateInfos and it contains caName and serialNumber
     */
    public CRLRequestMessage build() {
        final CRLRequestMessage crlRequestMessage = new CRLRequestMessage();

        crlRequestMessage.setCaCertificateInfoList(caCertificateInfos);
        return crlRequestMessage;
    }
}