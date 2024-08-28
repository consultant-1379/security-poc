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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * CRLDistributionPointName is one of the field from CRLDistributionPoint as per RFC. One of the fullName/nameRelativeToCRLIssuer should be filled.
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="DistributionPointName">
 *   &lt;complexContent>
 *        &lt;sequence>
 *         &lt;element name="FullName" type="nonEmptyString" minOccurs="0" maxOccurs="unbounded"/>
 *         &lt;element name="NameRelativeToCRLIssuer" type="nonEmptyString" minOccurs="0"/>
 *       &lt;/sequence>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DistributionPointName", propOrder = { "fullName", "nameRelativeToCRLIssuer" })
public class CredentialManagerDistributionPointName implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 5824043673813858201L;
    @XmlElement(name = "FullName", required = false)
    private List<String> fullName = new ArrayList<String>();
    @XmlElement(name = "NameRelativeToCRLIssuer", required = false)
    private String nameRelativeToCRLIssuer;

    /**
     * @return the fullName
     */
    public List<String> getFullName() {
        return fullName;
    }

    /**
     * @param fullName
     *            the fullName to set
     */
    public void setFullName(final List<String> fullName) {
        this.fullName = fullName;
    }

    /**
     * @return the nameRelativeToCRLIssuer
     */
    public String getNameRelativeToCRLIssuer() {
        return nameRelativeToCRLIssuer;
    }

    /**
     * @param nameRelativeToCRLIssuer
     *            the nameRelativeToCRLIssuer to set
     */
    public void setNameRelativeToCRLIssuer(final String nameRelativeToCRLIssuer) {
        this.nameRelativeToCRLIssuer = nameRelativeToCRLIssuer;
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
        result = prime * result + ((fullName == null) ? 0 : fullName.hashCode());
        result = prime * result + ((nameRelativeToCRLIssuer == null) ? 0 : nameRelativeToCRLIssuer.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "DistributionPointName [" + ((null == fullName) ? "" : (" fullName=" + fullName))
                + ((null == nameRelativeToCRLIssuer) ? "" : (", nameRelativeToCRLIssuer=" + nameRelativeToCRLIssuer)) + "]";
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
        final CredentialManagerDistributionPointName other = (CredentialManagerDistributionPointName) obj;
        if (fullName == null) {
            if (other.fullName != null) {
                return false;
            }
        } else if (!fullName.equals(other.fullName)) {
            return false;
        }
        if (nameRelativeToCRLIssuer == null) {
            if (other.nameRelativeToCRLIssuer != null) {
                return false;
            }
        } else if (!nameRelativeToCRLIssuer.equals(other.nameRelativeToCRLIssuer)) {
            return false;
        }
        return true;
    }

}
