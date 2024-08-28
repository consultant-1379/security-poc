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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseMessage;

/**
 * This Class prepares the CRL Response Message Builder using list of CRL Information
 * 
 * @author xjagcho
 *
 */
public class CRLResponseMessageBuilder {
    private List<CRLInfo> crlInfos;

    /**
     * This method sets list crlInfos
     * 
     * @param crlInfos
     *            it contains list of CACertificateInfo and it holds caName and serialNumber and encoded CRL
     * 
     * @return CRLResponseMessageBuilder
     */
    public CRLResponseMessageBuilder crlInfos(final List<CRLInfo> crlInfos) {
        this.crlInfos = crlInfos;
        return this;
    }

    /**
     * This method builds the CRL Response Message using list CRL Information
     * 
     * @return CRLResponseMessage it holds list crlInfos and it contains CACertificateInfo and encoded CRL
     */
    public CRLResponseMessage build() {
        final CRLResponseMessage crlResponseMessage = new CRLResponseMessage();

        crlResponseMessage.setCrlInfoList(crlInfos);
        return crlResponseMessage;
    }
}