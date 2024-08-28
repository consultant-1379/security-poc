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
package com.ericsson.oss.itpf.security.pki.common.scep.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * ScepRequest is the request data holder which will be loaded from the XML request data which is received as part of ScepRequestMessage.
 * 
 * @author xnagsow
 *
 */
@XmlRootElement
public class ScepRequest {

    private String transactionId;
    private byte[] csr;

    /**
     * @return the transactionId
     */
    @XmlElement
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
     * @return the csr
     */
    @XmlElement
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
