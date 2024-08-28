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
package com.ericsson.oss.itpf.security.pki.common.model.certificate.extension;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

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
 *         &lt;element name="DistributionPoint" type="DistributionPoint"
 *                                                 minOccurs="1" maxOccurs="unbounded" />
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CRLDistributionPoints", propOrder = { "distributionPoints" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class CRLDistributionPoints extends CertificateExtension {

    /**
     * 
     */
    private static final long serialVersionUID = 2099556208136342324L;
    @XmlElement(name = "DistributionPoint", required = true)
    protected List<DistributionPoint> distributionPoints = new ArrayList<DistributionPoint>();

    /**
     * @return the CRLDistributionPoint
     */
    public List<DistributionPoint> getDistributionPoints() {
        return distributionPoints;
    }

    /**
     * @param CRLDistributionPoint
     *            the CRLDistributionPoint to set
     */
    public void setDistributionPoints(final List<DistributionPoint> distributionPoints) {
        this.distributionPoints = distributionPoints;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " [ Critical: " + critical + " CRL Distribution Points: " + distributionPoints.toString() + " ] ";
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
        result = prime * result + ((distributionPoints == null) ? 0 : distributionPoints.hashCode());
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
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CRLDistributionPoints other = (CRLDistributionPoints) obj;
        if (distributionPoints == null) {
            if (other.distributionPoints != null) {
                return false;
            }
        } else if (distributionPoints.size() != other.distributionPoints.size()) {
            return false;
        } else if (distributionPoints != null && other.distributionPoints != null) {
            boolean isMatched = false;
            for (final DistributionPoint cRLDistributionPoint : distributionPoints) {
                for (final DistributionPoint cRLDistributionPointOther : other.distributionPoints) {
                    if (cRLDistributionPoint.equals(cRLDistributionPointOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        return true;
    }
}
