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
 * This class defines model for RevocationServiceRequest.
 * 
 * @author tcsramc
 *
 */
@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "SignedRevocationServiceRequest", version = CMPModelConstants.VERSION, description = "This Event contains signed Revocation request which contains parameters required for Certificate revocation, which has to be  sent to PKI-Manager.")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceRequestChannel")
public class SignedRevocationServiceRequest implements Serializable {

    private static final long serialVersionUID = -3100055413364639876L;

    @EModelAttribute(description = "Signed Revocation request which is in the form of XML. It has to be sent to PKI-Manager.")
    @EventAttribute
    private byte[] revocationServiceRequest;

    /**
     * @return the revocationServiceRequest
     */
    public byte[] getRevocationServiceRequest() {
        return revocationServiceRequest;
    }

    /**
     * @param revocationRequest
     *            the revocationRequest to set
     */
    public void setRevocationServiceRequest(final byte[] revocationRequest) {
        this.revocationServiceRequest = revocationRequest;
    }

}
