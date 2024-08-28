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
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class defines model for CMPServiceRequest EventType.
 * 
 * @author tcsdemi
 *
 */
@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "SignedCMPServiceRequest", version = CMPModelConstants.VERSION, description = "SignedCMPServiceRequest Event sends the required signed information to Pki-manager for certificate generation.")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceRequestChannel")
public class SignedCMPServiceRequest implements Serializable {

    private static final long serialVersionUID = -3100055413364639876L;

    @EModelAttribute(description = "Signed CMP Request which is in the form of XML. It has to be sent to PKI-Manager")
    @EventAttribute
    private byte[] cmpRequest;

    /**
     * @return the cmpRequest
     */
    public byte[] getCmpRequest() {
        return cmpRequest;
    }

    /**
     * @param cmpRequest
     *            the cmpRequest to set
     */
    public void setCmpRequest(final byte[] cmpRequest) {
        this.cmpRequest = cmpRequest;
    }

}
