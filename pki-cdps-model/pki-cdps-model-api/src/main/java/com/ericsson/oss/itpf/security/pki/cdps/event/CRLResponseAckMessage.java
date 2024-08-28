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
package com.ericsson.oss.itpf.security.pki.cdps.event;

import java.util.List;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.constants.CDPSModelConstant;
import com.ericsson.oss.itpf.security.pki.cdps.edt.*;

/**
 *
 * CRLResponseAckMessage class is used as a CRLAcknowledgement message it has to be sent to PKI Manager over a CDPSManager Queue. CRLAcknowledgement has a holder to hold
 * CAName,CertificateSerialNumber,PublishCDPSStatus.
 * 
 * @author xnarsir
 */

@EModel(namespace = CDPSModelConstant.NAME_SPACE, name = "CRLResponseAckMessage", version = CDPSModelConstant.MODEL_VERSION, description = "CRL Acknowledgement Message")
@EventTypeDefinition(channelUrn = CDPSModelConstant.CRL_RESPONSE_ACK_CHANNEL_URN)
public class CRLResponseAckMessage {

    @EModelAttribute(description = "CACertificateInfo list object of CRLResponseAckMessage to be send over the ClusteredCRLResponseAckChannel", mandatory = true)
    @EventAttribute(filterable = false)
    List<CACertificateInfo> caCertificateInfoList;

    @EModelAttribute(description = "CRLPublishStatustype of CRLResponseAckMessage to be send over the ClusteredCRLResponseAckChannel", mandatory = true)
    @EventAttribute(filterable = false)
    CDPSOperationType cdpsOperationType;

    @EModelAttribute(description = "CDPSResponseType of CRLResponseAckMessage to be send over the ClusteredCRLResponseAckChannel", mandatory = true)
    @EventAttribute(filterable = false)
    CDPSResponseType cdpsResponseType;

    @EModelAttribute(description = "UnpublishReasonType of CRLResponseAckMessage to be send over the ClusteredCRLResponseAckChannel", mandatory = true)
    @EventAttribute(filterable = false)
    UnpublishReasonType unpublishReasonType;

    /**
     * @return the caCertificateInfoList
     */
    public List<CACertificateInfo> getCaCertificateInfoList() {
        return caCertificateInfoList;
    }

    /**
     * @param caCertificateInfoList
     *            the caCertificateInfoList to set
     */
    public void setCaCertificateInfoList(final List<CACertificateInfo> caCertificateInfoList) {
        this.caCertificateInfoList = caCertificateInfoList;
    }

    /**
     * @return the cdpsOperationType
     */
    public CDPSOperationType getCdpsOperationType() {
        return cdpsOperationType;
    }

    /**
     * @param cdpsOperationType
     *            the cdpsOperationType to set
     */
    public void setCdpsOperationType(final CDPSOperationType cdpsOperationType) {
        this.cdpsOperationType = cdpsOperationType;
    }

    /**
     * @return the cdpsResponseType
     */
    public CDPSResponseType getCdpsResponseType() {
        return cdpsResponseType;
    }

    /**
     * @param cdpsResponseType
     *            the cdpsResponseType to set
     */
    public void setCdpsResponseType(final CDPSResponseType cdpsResponseType) {
        this.cdpsResponseType = cdpsResponseType;
    }

    /**
     * @return the unpublishReasonType
     */
    public UnpublishReasonType getUnpublishReasonType() {
        return unpublishReasonType;
    }

    /**
     * @param unpublishReasonType
     *            the unpublishReasonType to set
     */
    public void setUnpublishReasonType(final UnpublishReasonType unpublishReasonType) {
        this.unpublishReasonType = unpublishReasonType;
    }
}
