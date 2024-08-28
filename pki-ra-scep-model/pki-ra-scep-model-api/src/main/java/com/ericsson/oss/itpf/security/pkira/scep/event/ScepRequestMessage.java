/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
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
 * Scep Request Message will send the CSR and the transactionId to be sent over the ScepRequestChannel. The ScepRequestMessage will be the holder to send the request for the generation of certificate
 * for the pki operation of pkcs request
 *
 * @author xananer
 */

// This event is deprecated and should not be used further.
@EModel(namespace = "pki-ra-scep", name = "ScepRequest", version = ScepModelConstant.MODEL_VERSION, description = "Scep Request Message")
@EventTypeDefinition(channelUrn = "//global/ClusteredScepRequestChannel")
public class ScepRequestMessage {

    @EModelAttribute(description = "CSR to be send over the Request Channel", mandatory = true)
    @EventAttribute(filterable = false)
    private byte[] csr;

    @EModelAttribute(description = "TransactionId to be sent over the Request Channel", mandatory = true)
    @EventAttribute(filterable = false)
    private String transactionId;

    /**
     * @return the transactionId
     */
    public String getTransactionId() {
        return transactionId;
    }

    /**
     * @param transactionId
     *            the transactionId to set
     */
    public void setTransactionId(final String transactionId) {
        this.transactionId = transactionId;
    }

    /**
     * @return the CSR
     */
    public byte[] getCsr() {
        return csr;
    }

    /**
     * @param csr
     *            the csr to set
     */
    public void setCsr(final byte[] csr) {
        this.csr = csr;
    }

}
