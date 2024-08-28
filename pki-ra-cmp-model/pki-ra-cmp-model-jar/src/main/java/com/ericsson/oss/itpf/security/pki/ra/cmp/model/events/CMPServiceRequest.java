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
package com.ericsson.oss.itpf.security.pki.ra.cmp.model.events;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.CMPRequest;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class defines model for CMPServiceRequest EventType. 1. transactionID as String 2. CMPRequest(cmpRequest) 3. syncRequest
 * 
 * @author tcsdemi
 *
 */
@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "CMPServiceRequest", version = CMPModelConstants.VERSION, description = "CMPServiceRequest Event sends the required information to Pki-manager for certificate generation.")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceRequestChannel")
public class CMPServiceRequest implements Serializable {

    private static final long serialVersionUID = -3100055413364639876L;

    @EModelAttribute(description = "This attribute is a Base64 encoded TransactionId and is maintained across a transaction initiated from Node, i.e from IR till PKIConf message")
    @EventAttribute
    private String transactionID;

    @EModelAttribute(description = "This is the actual PKIMessage which is to be sent over the queue CMPMessage is modeled as a ComplexDataType which consists of Encoded PKIMessage sent from EventSender")
    @EventAttribute
    private CMPRequest cmpRequest;

    @EModelAttribute(description = "This boolean attribute conveys whether node expects a synchronous response or an asynchronous response.")
    @EventAttribute
    private boolean syncRequest;

    public CMPRequest getCmpRequest() {
        return this.cmpRequest;
    }

    public void setCmpRequest(final CMPRequest cmpRequest) {
        this.cmpRequest = cmpRequest;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public void setTransactionID(final String transactionID) {
        this.transactionID = transactionID;
    }

    public boolean isSyncRequest() {
        return syncRequest;
    }

    public void setSyncRequest(final boolean syncRequest) {
        this.syncRequest = syncRequest;
    }

}
