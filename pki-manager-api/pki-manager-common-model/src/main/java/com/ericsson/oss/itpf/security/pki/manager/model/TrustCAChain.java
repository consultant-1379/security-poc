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
package com.ericsson.oss.itpf.security.pki.manager.model;

import java.io.Serializable;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * <p>
 * This class holds internal CAs along with a boolean attribute to indicate whether chain of certificates are required or not.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="TrustCAChain">
 *  &lt;complexContent>
 *    &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *              &lt;element name="IsChainRequired" type="xs:boolean" minOccurs="0" />
 *              &lt;element name="InternalCA" type="CAEntity" minOccurs="0" />
 *       &lt;/sequence>
 *    &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "TrustCAChain")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrustCAChain", propOrder = { "isChainRequired", "internalCA" })
public class TrustCAChain implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -3153055540398814077L;

    @XmlElement(name = "IsChainRequired", required = true)
    private boolean isChainRequired;
    @XmlElement(name = "InternalCA", required = true)
    private CAEntity internalCA;

    /**
     * @return the isChainRequired
     */
    public boolean isChainRequired() {
        return isChainRequired;
    }

    /**
     * @param isChainRequired
     *            the isChainRequired to set
     */
    public void setChainRequired(final boolean isChainRequired) {
        this.isChainRequired = isChainRequired;
    }

    /**
     * @return the internalCA
     */
    public CAEntity getInternalCA() {
        return internalCA;
    }

    /**
     * @param internalCA
     *            the internalCA to set
     */
    public void setInternalCA(final CAEntity internalCA) {
        this.internalCA = internalCA;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "TrustCAChain [isChainRequired=" + isChainRequired + ", " + (internalCA != null ? "internalCA=" + internalCA : "") + "]";
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
        result = prime * result + ((internalCA == null) ? 0 : internalCA.hashCode());
        result = prime * result + (isChainRequired ? 1231 : 1237);
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
        final TrustCAChain other = (TrustCAChain) obj;
        if (internalCA == null) {
            if (other.internalCA != null) {
                return false;
            }
        } else if (!internalCA.equals(other.internalCA)) {
            return false;
        }
        if (isChainRequired != other.isChainRequired) {
            return false;
        }
        return true;
    }
}
