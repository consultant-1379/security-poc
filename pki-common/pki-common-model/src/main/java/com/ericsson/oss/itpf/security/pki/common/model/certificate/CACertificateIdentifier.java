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
 * This class contains the fields which are used to identify the Certificate to generate CRL.
 * 
 * <ul>
 * <li>cerficateSerialNumber : Serial Number of the Certificate.</li>
 * <li>caName : Issuer Name of Certificate.</li>
 * </ul>
 * This is used to represent the Certificate identifier.
 * 
 */
public class CACertificateIdentifier implements Serializable {

    private static final long serialVersionUID = 1782531313129797179L;

    private String caName;

    private String cerficateSerialNumber;

	public CACertificateIdentifier() {
        super();
    }

    /**
     * @param caName
     * @param cerficateSerialNumber
     */
    public CACertificateIdentifier(final String caName, final String cerficateSerialNumber) {
        super();
        this.caName = caName;
        this.cerficateSerialNumber = cerficateSerialNumber;
    }
	
    /**
     * @return the caName
     */
    public String getCaName() {
        return caName;
    }

    /**
     * @param caName
     *            the caName to set
     */
    public void setCaName(final String caName) {
        this.caName = caName;
    }

    /**
     * @return the cerficateSerialNumber
     */
    public String getCerficateSerialNumber() {
        return cerficateSerialNumber;
    }

    /**
     * @param cerficateSerialNumber
     *            the cerficateSerialNumber to set
     */
    public void setCerficateSerialNumber(final String cerficateSerialNumber) {
        this.cerficateSerialNumber = cerficateSerialNumber;
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
        result = prime * result + ((caName == null) ? 0 : caName.hashCode());
        result = prime * result + ((cerficateSerialNumber == null) ? 0 : cerficateSerialNumber.hashCode());
        return result;
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
        
        final CACertificateIdentifier other = (CACertificateIdentifier) obj;
        if (caName == null) {
            if (other.caName != null) {
                return false;
            }
        } else if (!caName.equals(other.caName)) {
            return false;
        }
        
        if (cerficateSerialNumber == null) {
            if (other.cerficateSerialNumber != null) {
                return false;
            }
        } else if (!cerficateSerialNumber.equals(other.cerficateSerialNumber)) {
            return false;
        }
        
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CACertificateIdentifier [caName=" + caName + ", cerficateSerialNumber=" + cerficateSerialNumber + "]";
    }

}
