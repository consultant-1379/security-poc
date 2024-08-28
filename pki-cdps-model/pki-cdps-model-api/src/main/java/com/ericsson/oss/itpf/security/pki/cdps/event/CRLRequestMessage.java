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

/**
 *
 * CRLRequestMessage is the request message holder for which requests the notification is received. This CRL request message notification is sent over the CdpsManager channel. CRLNotificationMessage
 * will send the list of CACertificateInfo
 * 
 * @author xnarsir
 */

@EModel(namespace = CDPSModelConstant.NAME_SPACE, name = "CRLRequestMessage", version = CDPSModelConstant.MODEL_VERSION, description = "Cdps sends an event to PKI Manager to get the CRL")
@EventTypeDefinition(channelUrn = CDPSModelConstant.CRL_REQUEST_CHANNEL_URN)
public class CRLRequestMessage {

    @EModelAttribute(description = "CACertificateInfo list object of CRLRequestMessage to be send over the ClusteredCRLRequestChannel", mandatory = true)
    @EventAttribute(filterable = false)
    List<CACertificateInfo> caCertificateInfoList;

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

}
