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
 * This class defines model for CMPServiceResponse EventType.
 * 
 * @author tcsdemi
 *
 */

@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, name = "SignedCMPServiceResponse", version = CMPModelConstants.VERSION, description = "This event contains signed Response sent by PKI-Manager")
@EventTypeDefinition(channelUrn = "//global/ClusteredCMPServiceResponseChannel")
public class SignedCMPServiceResponse implements Serializable {

    private static final long serialVersionUID = -4084108991622857777L;

    @EModelAttribute(description = "Signed CMP Response which is in the form of XML. It is obtained from PKI-Manager.")
    @EventAttribute
    private byte[] cmpResponse;

    /**
     * @return the cmpResponse
     */
    public byte[] getCmpResponse() {
        return cmpResponse;
    }

    /**
     * @param cmpResponse
     *            the cmpResponse to set
     */
    public void setCmpResponse(final byte[] cmpResponse) {
        this.cmpResponse = cmpResponse;
    }

}
