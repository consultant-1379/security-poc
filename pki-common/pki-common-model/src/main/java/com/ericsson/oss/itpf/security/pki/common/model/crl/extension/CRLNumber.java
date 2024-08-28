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
package com.ericsson.oss.itpf.security.pki.common.model.crl.extension;

import java.io.Serializable;

/**
 * This Class contains all the attributes of a CRLNumber as mentioned below.
 * 
 * <ul>
 * <li>critical : if true, it holds good for CRL Extensions</li>
 * <li>serialNumber : Serial number of the CRL.</li>
 * </ul>
 * 
 */
public class CRLNumber implements Serializable{

 private static final long serialVersionUID = 2262506806896764381L;

    private boolean critical;
    private Integer serialNumber;

    /**
     * @return the critical
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * @param critical
     *            the critical to set
     */
    public void setCritical(final boolean critical) {
        this.critical = critical;
    }

    /**
     * @return the serialNumber
     */
    public Integer getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final Integer serialNumber) {
        this.serialNumber = serialNumber;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CRLNumber [critical=" + critical + ", serialNumber=" + serialNumber + "]";
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
        result = prime * result + (critical ? 1231 : 1237);
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
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
        
        final CRLNumber other = (CRLNumber) obj;
        if (critical != other.critical) {
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

}
