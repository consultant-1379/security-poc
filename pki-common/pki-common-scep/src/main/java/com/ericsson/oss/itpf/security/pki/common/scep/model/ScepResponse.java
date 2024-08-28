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
 * ScepResponse is the response data holder which will be loaded from the XML response data which is received as part of ScepResponseMessage.
 * 
 * @author xnagsow
 *
 */
@XmlRootElement
public class ScepResponse {

    private String transactionId;
    private int status;
    private byte[] certificate;
    private String failureInfo;

    /**
     * @return the transactionId
     */
    @XmlElement
    public String getTransactionId() {
        return this.transactionId;
    }

    /**
     * @param transactionId
     *            the transactionId to set
     */
    public void setTransactionId(final String transactionId) {
        this.transactionId = transactionId;
    }

    /**
     * @return the status
     */
    @XmlElement
    public int getStatus() {
        return this.status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final int status) {
        this.status = status;
    }

    /**
     * @return the certificate
     */
    @XmlElement
    public byte[] getCertificate() {
        return this.certificate;
    }

    /**
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(final byte[] certificate) {
        this.certificate = certificate;
    }

    /**
     * @return the failureInfo
     */
    @XmlElement
    public String getFailureInfo() {
        return this.failureInfo;
    }

    /**
     * @param failureInfo
     *            the failureInfo to set
     */
    public void setFailureInfo(final String failureInfo) {
        this.failureInfo = failureInfo;
    }

}
