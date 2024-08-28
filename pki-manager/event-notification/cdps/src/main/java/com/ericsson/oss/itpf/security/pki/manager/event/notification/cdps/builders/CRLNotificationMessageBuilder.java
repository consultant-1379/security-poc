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

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLNotificationMessage;

/**
 * This Class prepares the CRL Notification Message Builder using list of CACertificateInfo,CDPSOperationType and UnpublishReasonType
 * 
 * @author xjagcho
 *
 */
public class CRLNotificationMessageBuilder {
    private List<CACertificateInfo> caCertificateInfos;
    private CDPSOperationType cdpsOperationType;
    private UnpublishReasonType unpublishReasonType;

    /**
     * This method sets list caCertificateInfos
     * 
     * @param caCertificateInfos
     *            it contains list of CACertificateInfo and it holds caName and serialNumber
     * 
     * @return CRLNotificationMessageBuilder
     */
    public CRLNotificationMessageBuilder caCertificateInfos(final List<CACertificateInfo> caCertificateInfos) {
        this.caCertificateInfos = caCertificateInfos;
        return this;
    }

    /**
     * This method sets CDPS Operation Type
     * 
     * @return CRLNotificationMessageBuilder
     */
    public CRLNotificationMessageBuilder cdpsOperationType(final CDPSOperationType cdpsOperationType) {
        this.cdpsOperationType = cdpsOperationType;
        return this;
    }

    /**
     * This method sets unPublish ReasonType
     * 
     * @return CRLNotificationMessageBuilder
     */
    public CRLNotificationMessageBuilder unpublishReasonType(final UnpublishReasonType unpublishReasonType) {
        this.unpublishReasonType = unpublishReasonType;
        return this;
    }

    /**
     * This method builds the CRL Notification Message using list caCertificateInfos and cdpsOperationType
     * 
     * @return CRLNotificationMessage it holds list caCertificateInfos and it contains caName and serialNumber and cdpsOperationType
     */
    public CRLNotificationMessage build() {
        final CRLNotificationMessage crlNotificationMessage = new CRLNotificationMessage();

        crlNotificationMessage.setCaCertificateInfoList(caCertificateInfos);
        crlNotificationMessage.setCdpsOperationType(cdpsOperationType);
        crlNotificationMessage.setUnpublishReasonType(unpublishReasonType);
        return crlNotificationMessage;
    }
}
