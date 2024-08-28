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
 * This class holds all revocation response data that has been sent by PKI-Manager to CMP.Response will be in the form of marshalled XML document signed by manager certificate which indicates secure
 * communication is established between CMP and Manager.
 * 
 * @author tcsramc
 *
 */
@XmlRootElement
public class RevocationResponse {
    private boolean isRevoked;
    private String transactionID;
    private String subjectName;

    /**
     * @return the isRevoked
     */
    @XmlElement
    public boolean isRevoked() {
        return isRevoked;
    }

    /**
     * @param isRevoked
     *            the isRevoked to set
     */
    public RevocationResponse setRevoked(final boolean isRevoked) {
        this.isRevoked = isRevoked;
        return this;
    }

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
     */
    public RevocationResponse setTransactionID(final String transactionID) {
        this.transactionID = transactionID;
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
    public RevocationResponse setSubjectName(final String subjectName) {
        this.subjectName = subjectName;
        return this;
    }
}
