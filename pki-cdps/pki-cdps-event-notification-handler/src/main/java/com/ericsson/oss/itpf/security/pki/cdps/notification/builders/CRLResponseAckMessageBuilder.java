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
import com.ericsson.oss.itpf.security.pki.cdps.edt.*;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;

/**
 * This Class prepares the CRL ResponseAckMessage Builder using list of CACertificateInfo,CDPSOperationType and CDPSResponseType,UnpublishReasonType
 * 
 * @author xjagcho
 *
 */
public class CRLResponseAckMessageBuilder {
    private List<CACertificateInfo> caCertificateInfos;
    private CDPSOperationType cdpsOperationType;
    private CDPSResponseType cdpsResponseType;
    private UnpublishReasonType unpublishReasonType;

    /**
     * This sets the cdpsResponseType
     * 
     * @param caCertificateInfos
     *            it holds the list of CACertificateInfo it contains caName and serialNumber
     * @return CRLResponseAckMessageBuilder
     */
    public CRLResponseAckMessageBuilder caCertificateInfos(final List<CACertificateInfo> caCertificateInfos) {
        this.caCertificateInfos = caCertificateInfos;
        return this;
    }

    /**
     * This sets the cdpsResponseType
     * 
     * @param CDPSOperationType
     *            type of the response publish or unPublish
     * @return CRLResponseAckMessageBuilder
     */
    public CRLResponseAckMessageBuilder cdpsOperationType(final CDPSOperationType cdpsOperationType) {
        this.cdpsOperationType = cdpsOperationType;
        return this;
    }

    /**
     * This sets the cdpsResponseType
     * 
     * @param cdpsResponseType
     *            type of the response success or failure
     * @return CRLResponseAckMessageBuilder
     */
    public CRLResponseAckMessageBuilder cdpsResponseType(final CDPSResponseType cdpsResponseType) {
        this.cdpsResponseType = cdpsResponseType;
        return this;
    }

    /**
     * This sets the UnpublishReasonType
     * 
     * @param unpublishReasonType
     *            type of the UnPublish CRL Reason REVOKED_CA_CERTIFICATE or EXPIRED_CA_CERTIFICATE
     * @return CRLResponseAckMessageBuilder
     */
    public CRLResponseAckMessageBuilder unpublishReasonType(final UnpublishReasonType unpublishReasonType) {
        this.unpublishReasonType = unpublishReasonType;
        return this;
    }

    /**
     * This method builds the CRLResponseAckMessage
     * 
     * @return CRLResponseAckMessage it holds list caCertificateInfos,cdpsOperationType and cdpsResponseType,crlUnpublishReasonType
     */
    public CRLResponseAckMessage build() {
        final CRLResponseAckMessage crlResponseAckMessage = new CRLResponseAckMessage();

        crlResponseAckMessage.setCaCertificateInfoList(caCertificateInfos);
        crlResponseAckMessage.setCdpsOperationType(cdpsOperationType);
        crlResponseAckMessage.setCdpsResponseType(cdpsResponseType);
        crlResponseAckMessage.setUnpublishReasonType(unpublishReasonType);
        return crlResponseAckMessage;
    }
}
