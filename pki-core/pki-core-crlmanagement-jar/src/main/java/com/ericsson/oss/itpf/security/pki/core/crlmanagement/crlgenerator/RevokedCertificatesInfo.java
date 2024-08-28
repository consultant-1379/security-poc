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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import java.io.Serializable;
import java.util.Date;

/**
 * 
 * This is the holder class for the revoked certificates which contains the Certificate Serial Number , revocationDate , RevocationReason, invalidityDate
 * 
 * @author xananer
 *
 */
public class RevokedCertificatesInfo implements Serializable {

    private static final long serialVersionUID = -8262747932328138293L;

    private String serialNumber;

    private Date revocationDate;

    private int revocationReason;

    private Date invalidityDate;

    /**
     * @return the revocationDate
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * @param revocationDate
     *            the revocationDate to set
     */
    public void setRevocationDate(final Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    /**
     * @return the serialNumber
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the revocationReason
     */
    public int getRevocationReason() {
        return revocationReason;
    }

    /**
     * @param revocationReason
     *            the revocationReason to set
     */
    public void setRevocationReason(final int revocationReason) {
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
        result = prime * result + ((revocationDate == null) ? 0 : revocationDate.hashCode());
        result = prime * result + revocationReason;
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
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

        final RevokedCertificatesInfo other = (RevokedCertificatesInfo) obj;
        if (invalidityDate == null) {
            if (other.invalidityDate != null) {
                return false;
            }
        } else if (!invalidityDate.equals(other.invalidityDate)) {
            return false;
        }

        if (revocationDate == null) {
            if (other.revocationDate != null) {
                return false;
            }
        } else if (!revocationDate.equals(other.revocationDate)) {
            return false;
        }

        if (revocationReason != other.revocationReason) {
            return false;
        }

        if (serialNumber == null) {
            if (other.serialNumber != null) {
                return false;
            }
        } else if (!serialNumber.equals(other.serialNumber)) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return "CRLEntryExtensionHolder [serialNumber=" + serialNumber + ", revocationReason=" + revocationReason + ", invalidityDate=" + invalidityDate + ", revocationDate=" + revocationDate + "]";
    }

}
