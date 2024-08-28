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
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class defines the model for RevocationServiceResponse.Response Event Contains <br/>
 * 1. isRevoked(responsible for specifying PKI-RA, whether Certificate is revoked or not.) <br/>
 * 2. transactionId <br/>
 * 3. SenderName.
 * 
 * @author tcsramc
 *
 */
@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "RevocationServiceResponseEvent", version = CMPModelConstants.VERSION, description = "This event contains the revocation response sent by PKI-Manager.")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceResponseChannel")
public class RevocationServiceResponseEvent implements Serializable {

    private static final long serialVersionUID = 7340282520042360846L;
    @EModelAttribute(description = "isRevoked")
    @EventAttribute
    private boolean isRevoked;

    @EModelAttribute(description = "transactionID")
    @EventAttribute
    private String transactionID;

    @EModelAttribute(description = "subjectName")
    @EventAttribute
    private String subjectName;

    /**
     * @return the subjectName
     */
    public String getSubjectName() {
        return subjectName;
    }

    /**
     * @param subjectName
     *            the subjectName to set
     */
    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    /**
     * @return the transactionId
     */
    public String getTransactionID() {
        return transactionID;
    }

    /**
     * @param transactionId
     *            the transactionId to set
     */
    public void setTransactionID(String transactionId) {
        this.transactionID = transactionId;
    }

    /**
     * @return the isRevoked
     */
    public boolean isRevoked() {
        return isRevoked;
    }

    /**
     * @param isRevoked
     *            the isRevoked to set
     */
    public void setRevoked(boolean isRevoked) {
        this.isRevoked = isRevoked;
    }

}
