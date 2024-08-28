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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

import java.io.Serializable;

/**
 * This class containing all Certificate fields which are used to identify the Certificate to revoke it.
 * 
 * <ul>
 * <li>Serial Number : Serial Number of the Certificate.</li>
 * <li>Issued Name : Issuer Name of Certificate.</li>
 * </ul>
 * This is used to represent the Certificate identifier.
 * 
 */
public class CertificateIdentifier implements Serializable {

    private static final long serialVersionUID = -5351501728996835523L;

    private String issuerName;

    private String serialNumber;

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CertificateIdentifier [" + (null != issuerName ? "issuerName=" + issuerName + ", " : "") + (null != serialNumber ? "serialNumber=" + serialNumber + ", " : "") + "]";
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
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
        
        final CertificateIdentifier other = (CertificateIdentifier) obj;
        if (issuerName == null) {
            if (other.issuerName != null) {
                return false;
            }
        } else if (!issuerName.equals(other.issuerName)) {
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((issuerName == null) ? 0 : issuerName.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        return result;
    }

}
