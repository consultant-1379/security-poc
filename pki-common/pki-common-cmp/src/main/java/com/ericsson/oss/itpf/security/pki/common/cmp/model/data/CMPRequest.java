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
package com.ericsson.oss.itpf.security.pki.common.cmp.model.data;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This class is used to hold all the data that is required to send to PKI-MANAGER over the queue. The object of this class is marshaled to XML Document and signed by CMP certificate so as to
 * facilitate secure communication between CMP and Manager
 * 
 * @author tcschdy
 *
 */
@XmlRootElement
public class CMPRequest {

    private String transactionId;
    private byte[] cmpRequest;
    private int requestType;
    private boolean syncRequest;
    private String issuerName;

    /**
     * @return the issuerName
     */
    @XmlElement
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     * @return CMPRequest.
     */
    public CMPRequest setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
        return this;
    }

    /**
     * @return the syncRequest
     */
    @XmlElement
    public boolean getSyncRequest() {
        return syncRequest;
    }

    /**
     * @param syncRequest
     *            the syncRequest to set
     * @return CMPRequest.
     */
    public CMPRequest setSyncRequest(final boolean syncRequest) {
        this.syncRequest = syncRequest;
        return this;
    }

    /**
     * @return the requestType
     */
    @XmlElement
    public int getRequestType() {
        return requestType;
    }

    /**
     * @param requestType
     *            the requestType to set
     * @return CMPRequest
     */
    public CMPRequest setRequestType(final int requestType) {
        this.requestType = requestType;
        return this;
    }

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
     * @return CMPRequest
     */
    public CMPRequest setTransactionId(final String transactionId) {
        this.transactionId = transactionId;
        return this;
    }

    /**
     * @return the cmpRequestArray
     */
    @XmlElement
    public byte[] getCmpRequest() {
        return cmpRequest;
    }

    /**
     * @param cmpRequestArray
     *            the cmpRequestArray to set
     * @return CMPRequest
     */
    public CMPRequest setCmpRequest(final byte[] cmpRequestArray) {
        this.cmpRequest = cmpRequestArray;
        return this;
    }

}