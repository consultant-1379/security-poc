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
package com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This class is used to hold all the data that is required for PKI-Manager to perform revocation operation. Revocation request will be in the form of marshaled XML Document and signed by CMP
 * certificate so as to facilitate secure communication between CMP and Manager
 * 
 * @author tcsramc
 *
 */
@XmlRootElement
public class RevocationRequest {
    private String issuerName;
    private String serialNumber;
    private String transactionId;
    private String subjectName;
    private String revocationReason;
    private String invalidityDate;

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
     */
    public RevocationRequest setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
        return this;
    }

    /**
     * @return the serialNumber
     */
    @XmlElement
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public RevocationRequest setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
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
     */
    public RevocationRequest setTransactionId(final String transactionId) {
        this.transactionId = transactionId;
        return this;
    }

    /**
     * @return the subjectName
     */
    @XmlElement
    public String getSubjectName() {
        return subjectName;
    }

    /**
     * @param subjectName
     *            the subjectName to set
     */
    public RevocationRequest setSubjectName(final String subjectName) {
        this.subjectName = subjectName;
        return this;
    }

    /**
     * @return the revocationReason
     */
    @XmlElement
    public String getRevocationReason() {
        return revocationReason;
    }

    /**
     * @param revocationReason
     *            the revocationReason to set
     */
    public RevocationRequest setRevocationReason(final String revocationReason) {
        this.revocationReason = revocationReason;
        return this;
    }

    /**
     * @return the invalidityDate
     */
    @XmlElement
    public String getInvalidityDate() {
        return invalidityDate;
    }

    /**
     * @param invalidityDate
     *            the invalidityDate to set
     */
    public RevocationRequest setInvalidityDate(final String invalidityDate) {
        this.invalidityDate = invalidityDate;
        return this;
    }

}
