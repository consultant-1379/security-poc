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
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.constants.CDPSModelConstant;

/**
 * CRLResponseMessage has a holder it holds CAName,Certificate Serial Number, and CRL byte array. PKI Manager is used this CRLMessage that is to be send to CDPS over the ManagerCDPS channel.
 * 
 * @author xnarsir
 */

@EModel(namespace = CDPSModelConstant.NAME_SPACE, name = "CRLResponseMessage", version = CDPSModelConstant.MODEL_VERSION, description = "Crl Notification Message")
@EventTypeDefinition(channelUrn = CDPSModelConstant.CRL_RESPONSE_CHANNEL_URN)
public class CRLResponseMessage {

    @EModelAttribute(description = "CRLInfo list object of CRLResponseAckMessage to be send over the ClusteredCRLResponseChannel", mandatory = true)
    @EventAttribute(filterable = false)
    List<CRLInfo> crlInfoList;

    /**
     * @return the crlInfoList
     */
    public List<CRLInfo> getCrlInfoList() {
        return crlInfoList;
    }

    /**
     * @param crlInfoList
     *            the crlInfoList to set
     */
    public void setCrlInfoList(final List<CRLInfo> crlInfoList) {
        this.crlInfoList = crlInfoList;
    }
}
