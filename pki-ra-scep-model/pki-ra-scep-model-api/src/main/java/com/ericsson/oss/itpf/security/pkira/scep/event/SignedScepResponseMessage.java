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
 *
 * SignedScepResponseMessage will send the Digitally signed xml as the response message over the ScepResponseChannel. The response message will carry the data(TransactionId, Certificate, Status and
 * FailureInfo)
 * 
 * @author xnagsow
 */

@EModel(namespace = "pki-ra-scep", name = "SignedScepReponse", version = ScepModelConstant.MODEL_VERSION, description = "Signed Scep Response Message")
@EventTypeDefinition(channelUrn = "//global/ClusteredScepResponseChannel")
public class SignedScepResponseMessage {

    @EModelAttribute(description = "Digitally signed xml as the response message to be send over the Response Channel", mandatory = true)
    @EventAttribute(filterable = false)
    private byte[] scepResponse;

    /**
     * @return the scepResponse
     */
    public byte[] getScepResponse() {
        return scepResponse;
    }

    /**
     * @param scepResponse
     *            the scepResponse to set
     */
    public void setScepResponse(final byte[] scepResponse) {
        this.scepResponse = scepResponse;
    }
}