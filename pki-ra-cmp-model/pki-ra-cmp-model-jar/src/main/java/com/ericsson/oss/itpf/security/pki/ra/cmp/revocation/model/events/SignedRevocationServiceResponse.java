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
 * This class defines the model for RevocationServiceResponse.
 * 
 * @author tcsramc
 *
 */
@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "SignedRevocationServiceResponse", version = CMPModelConstants.VERSION, description = "This event contains the signed revocation response sent by PKI-Manager.")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceResponseChannel")
public class SignedRevocationServiceResponse implements Serializable {

    private static final long serialVersionUID = -3100055413364639876L;

    @EModelAttribute(description = "Signed Revocation response which is in the form of XML. It is obtained from PKI-Manager")
    @EventAttribute
    private byte[] revocationServiceResponse;

    /**
     * @return the revocationServiceResponse
     */
    public byte[] getRevocationServiceResponse() {
        return revocationServiceResponse;
    }

    /**
     * @param revocationServiceResponse
     *            the revocationServiceResponse to set
     */
    public void setRevocationServiceResponse(byte[] revocationServiceResponse) {
        this.revocationServiceResponse = revocationServiceResponse;
    }

}
