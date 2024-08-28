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
package com.ericsson.oss.itpf.security.pki.ra.scep.data;

import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.FailureInfo;

/**
 * This class contains the data related to Attributes which will be present in the SignerInformation of SCEP CertResp Message. This data is be used to build build the response.
 *
 * @author xshaeru
 */
public class SignerInfoAttributeData {

    private String transactionId;
    private ResponseStatus status;
    private byte[] recipientNonce;
    private FailureInfo failInfo;
    private String digestAlgorithm;

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
     * @return the status
     */
    public ResponseStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final ResponseStatus status) {
        this.status = status;
    }

    /**
     * @return the recipientNonce
     */
    public byte[] getRecipientNonce() {
        return recipientNonce;
    }

    /**
     * @param recipientNonce
     *            the recipientNonce to set
     */
    public void setRecipientNonce(final byte[] recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    /**
     * @return the failInfo
     */
    public FailureInfo getFailInfo() {
        return failInfo;
    }

    /**
     * @param failInfo
     *            the failInfo to set
     */
    public void setFailInfo(final FailureInfo failInfo) {
        this.failInfo = failInfo;
    }

    /**
     * @return the digestAlgorithm
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @param digestAlgorithm
     *            the digestAlgorithm to set
     */
    public void setDigestAlgorithm(final String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }
}
