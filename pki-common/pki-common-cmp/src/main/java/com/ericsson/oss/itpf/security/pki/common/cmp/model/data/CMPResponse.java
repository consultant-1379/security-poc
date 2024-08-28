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
 * This class is used to hold all the data that is required to send from PKI-MANAGER to CMP over the queue. The object of this class is marshaled to XML Document and signed by Manager certificate so
 * as to facilitate secure communication between CMP and Manager
 * 
 * @author tcschdy
 */

@XmlRootElement
public class CMPResponse {

    private String transactionID;
    private byte[] cmpResponse;
    private byte[] protectionAlgorithm;
    private int responseType;
    private String errorInfo;
    private String entityName;
    private String issuerName;
    private boolean syncResponse;

    /**
     * @return the transactionID
     */
    @XmlElement
    public String getTransactionID() {
        return transactionID;
    }

    /**
     * @param transactionID
     *            the transactionID to set
     * @return CMPResponse
     */

    public CMPResponse setTransactionID(final String transactionID) {
        this.transactionID = transactionID;
        return this;
    }

    /**
     * @return the syncResponse
     */
    @XmlElement
    public boolean getSyncResponse() {
        return syncResponse;
    }

    /**
     * @param syncResponse
     *            syncResponse to set
     * @return CMPResponse
     */

    public CMPResponse setSyncResponse(final boolean syncResponse) {
        this.syncResponse = syncResponse;
        return this;
    }

    /**
     * @return the cmpResponse
     */
    @XmlElement
    public byte[] getCmpResponse() {
        return cmpResponse;
    }

    /**
     * @param cmpResponse
     *            the cmpResponse to set
     * @return CMPResponse
     */
    public CMPResponse setCmpResponse(final byte[] cmpResponse) {
        this.cmpResponse = cmpResponse;
        return this;
    }

    /**
     * @return the protectionAlgorithm
     */
    @XmlElement
    public byte[] getProtectionAlgorithm() {
        return protectionAlgorithm;
    }

    /**
     * @param protectionAlgorithm
     *            the protectionAlgorithm to set
     * @return CMPResponse
     */
    public CMPResponse setProtectionAlgorithm(final byte[] protectionAlgorithm) {
        this.protectionAlgorithm = protectionAlgorithm;
        return this;
    }

    /**
     * @return the responseType
     */
    @XmlElement
    public int getResponseType() {
        return responseType;
    }

    /**
     * @param responseType
     *            the responseType to set
     * @return CMPResponse
     */
    public CMPResponse setResponseType(final int responseType) {
        this.responseType = responseType;
        return this;
    }

    /**
     * @return the errorInfo
     */
    @XmlElement
    public String getErrorInfo() {
        return errorInfo;
    }

    /**
     * @param errorInfo
     *            the errorInfo to set
     * @return CMPResponse
     */
    public CMPResponse setErrorInfo(final String errorInfo) {
        this.errorInfo = errorInfo;
        return this;
    }

    /**
     * @return the entityName
     */
    @XmlElement
    public String getEntityName() {
        return entityName;
    }

    /**
     * @param entityName
     *            the entityName to set
     * @return CMPResponse
     */
    public CMPResponse setEntityName(final String entityName) {
        this.entityName = entityName;
        return this;
    }

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
     * @return CMPResponse
     */
    public CMPResponse setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
        return this;
    }

}
