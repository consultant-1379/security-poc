/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pkira.scep.event;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.EModelAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventAttribute;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pkira.scep.constants.ScepModelConstant;

/**
 * SignedScepRequestMessage will send the Digitally signed xml as the request message over the ScepRequestChannel. The request message will carry the data(transactionId and CSR) required for the generation
 * of certificate.
 *
 * @author xnagsow
 */

@EModel(namespace = "pki-ra-scep", name = "SignedScepRequest", version = ScepModelConstant.MODEL_VERSION, description = "Signed Scep Request Message")
@EventTypeDefinition(channelUrn = "//global/ClusteredScepRequestChannel")
public class SignedScepRequestMessage {

    @EModelAttribute(description = "Digitally signed xml as the request message to be sent over the Request Channel", mandatory = true)
    @EventAttribute(filterable = false)
    private byte[] scepRequest;

    /**
     * @return the scepRequest
     */
    public byte[] getScepRequest() {
        return scepRequest;
    }

    /**
     * @param scepRequest
     *            the scepRequest to set
     */
    public void setScepRequest(final byte[] scepRequest) {
        this.scepRequest = scepRequest;
    }
}
