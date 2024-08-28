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
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;

/**
 * PKI Manager uses this CRLNotificationMessage class to send a CRL notification from PKI Manager to CDPS.When it receives a CRL from PKI Core. CRLNotificationMessage will send the list of
 * CACertificateInfo and the CDPSOperationType to be Sent over the ManagerCdps channel. CRLNotificationMessage contains an information for which CA that CRL is generated.
 * 
 * @author xnarsir
 */
@EModel(namespace = CDPSModelConstant.NAME_SPACE, name = "CRLNotificationMessage", version = CDPSModelConstant.MODEL_VERSION, description = "Crl Notification Message")
@EventTypeDefinition(channelUrn = CDPSModelConstant.CRL_NOTIFICATION_CHANNEL_URN)
public class CRLNotificationMessage {

    @EModelAttribute(description = "CACertificateInfo list object of CRLNotificationMessage to be send over the ClusteredCRLNotificationChannel", mandatory = true)
    @EventAttribute(filterable = false)
    List<CACertificateInfo> caCertificateInfoList;

    @EModelAttribute(description = "CRLPublishStatustype of CRLNotificationMessage to be send over the ClusteredCRLNotificationChannel", mandatory = true)
    @EventAttribute(filterable = false)
    CDPSOperationType cdpsOperationType;

    @EModelAttribute(description = "UnpublishReasonType of CRLNotificationMessage to be send over the ClusteredCRLNotificationChannel", mandatory = true)
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
     * @return the UnpublishReasonType
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
