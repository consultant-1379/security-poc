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
package com.ericsson.oss.itpf.security.pki.common.model.crl;

import java.io.Serializable;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;

/**
 * This Class contains all the attributes of a CRL as mentioned below.
 * 
 * <ul>
 * <li>x509CRLHolder : X509CRLHolder Instance.</li>
 * </ul>
 * This is used to represent the CRL data of end entity/ CA entity.
 * 
 */
public class CRL implements Serializable {

    private static final long serialVersionUID = -7638098697874808191L;

    private long id;

    private X509CRLHolder x509CRLHolder;

    /**
     * @return the id
     */
    public long getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * @return the x509CRLHolder
     */
    public X509CRLHolder getX509CRLHolder() {
        return x509CRLHolder;
    }

    /**
     * @param x509crlHolder
     *            the x509CRLHolder to set
     */
    public void setX509CRLHolder(final X509CRLHolder x509crlHolder) {
        x509CRLHolder = x509crlHolder;
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
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((x509CRLHolder == null) ? 0 : x509CRLHolder.hashCode());
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
        
        final CRL other = (CRL) obj;
        if (id != other.id) {
            return false;
        }
        
        if (x509CRLHolder == null) {
            if (other.x509CRLHolder != null) {
                return false;
            }
        } else if (!x509CRLHolder.equals(other.x509CRLHolder)) {
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
        return "CRL [id=" + id + ", x509CRLHolder=" + x509CRLHolder + "]";
    }

}
