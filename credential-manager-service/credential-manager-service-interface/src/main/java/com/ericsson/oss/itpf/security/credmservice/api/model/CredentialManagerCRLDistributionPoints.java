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

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;

/**
 * <p>
 * CRLDistributionPoints Certificate extension contains List of CRLDistributionPoint.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="CRLDistributionPoints">
 *   &lt;complexContent>
 *     &lt;extension base="{}CertificateExtension">
 *       &lt;sequence>
 *         &lt;element name="CRLDistributionPoint" type="CRLDistributionPoint"
 *                                                 minOccurs="1" maxOccurs="unbounded" />
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */

public class CredentialManagerCRLDistributionPoints extends CredentialManagerCertificateExtension {

    /**
     * 
     */
    private static final long serialVersionUID = 2099556208136342324L;
    @XmlElement(name = "CRLDistributionPoint", required = true)
    protected List<CredentialManagerCRLDistributionPoint> cRLDistributionPoints = new ArrayList<CredentialManagerCRLDistributionPoint>();

    /**
     * @return the CRLDistributionPoint
     */
    public List<CredentialManagerCRLDistributionPoint> getCRLDistributionPoints() {
        return cRLDistributionPoints;
    }

    /**
     * @param CRLDistributionPoint
     *            the CRLDistributionPoint to set
     */
    public void setCRLDistributionPoints(final List<CredentialManagerCRLDistributionPoint> cRLDistributionPoints) {
        this.cRLDistributionPoints = cRLDistributionPoints;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " [ Critical: " + critical + " CRL Distribution Points: " + cRLDistributionPoints.toString() + " ] ";
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((cRLDistributionPoints == null) ? 0 : cRLDistributionPoints.hashCode());
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
        final CredentialManagerCRLDistributionPoints other = (CredentialManagerCRLDistributionPoints) obj;
        if (cRLDistributionPoints == null) {
            if (other.cRLDistributionPoints != null) {
                return false;
            }
        } else if (!cRLDistributionPoints.equals(other.cRLDistributionPoints)) {
            return false;
        }
        return true;
    }

}
