/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model;

import java.io.Serializable;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;

/**
 * This class holds parameters required for renewal/rekey of CA certificate and revocation of existing CA certificate.
 * 
 */
public class CAReIssueInfo implements Serializable {

    private static final long serialVersionUID = -6156378288748043614L;

    /**
     * name of the CA
     */
    protected String name;

    /**
     * reasons for the Revocation which are defined in RFC5280..
     */
    protected RevocationReason revocationReason;

    /**
     * The date on which it is known or suspected that the private key was compromised or that the Certificate otherwise became invalid.
     */
    protected Date invalidityDate;

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * @return the revocationReason
     */
    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    /**
     * @param revocationReason
     *            the revocationReason to set
     */
    public void setRevocationReason(final RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    /**
     * @return the invalidityDate
     */
    public Date getInvalidityDate() {
        return invalidityDate;
    }

    /**
     * @param invalidityDate
     *            the invalidityDate to set
     */
    public void setInvalidityDate(final Date invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((invalidityDate == null) ? 0 : invalidityDate.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((revocationReason == null) ? 0 : revocationReason.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CAReIssueInfo other = (CAReIssueInfo) obj;
        if (invalidityDate == null) {
            if (other.invalidityDate != null) {
                return false;
            }
        } else if (!invalidityDate.equals(other.invalidityDate)) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (revocationReason != other.revocationReason) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "CAReIssueInfo [name=" + name + ", revocationReason=" + revocationReason + ", invalidityDate=" + invalidityDate + "]";
    }

}
