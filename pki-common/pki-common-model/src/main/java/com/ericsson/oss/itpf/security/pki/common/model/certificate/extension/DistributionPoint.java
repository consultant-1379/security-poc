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

import java.io.Serializable;

import javax.xml.bind.annotation.*;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * The CRL distribution points extension identifies how CRL information is obtained. User can mark this extension as critical/non-critical.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="DistributionPoint">
 *   &lt;complexContent>
 *       &lt;sequence>
 *         &lt;element  name="DistributionPointName" type="DistributionPointName" minOccurs="0"/>
 *         &lt;element name="ReasonFlag" type="ReasonFlag" minOccurs="0"/>
 *         &lt;element name="CRLIssuer" type="nonEmptyString" minOccurs="0"/>
 *       &lt;/sequence>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DistributionPoint", propOrder = { "distributionPointName", "reasonFlag", "cRLIssuer" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class DistributionPoint implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = 7472390148822641247L;

    @XmlElement(name = "DistributionPointName", required = false)
    protected DistributionPointName distributionPointName;
    @XmlElement(name = "CRLIssuer", required = false)
    protected String cRLIssuer;
    @XmlElement(name = "ReasonFlag", required = false)
    protected ReasonFlag reasonFlag;

    /**
     * @return the DistributionPointName
     */
    public DistributionPointName getDistributionPointName() {
        return distributionPointName;
    }

    /**
     * @param DistributionPointName
     *            the distributionPointName to set
     */
    public void setDistributionPointName(final DistributionPointName distributionPointName) {
        this.distributionPointName = distributionPointName;
    }

    /**
     * @return the CRLIssuer
     */
    public String getCRLIssuer() {
        return cRLIssuer;
    }

    /**
     * @param CRLIssuer
     *            the CRLIssuer to set
     */
    public void setCRLIssuer(final String cRLIssuer) {
        this.cRLIssuer = cRLIssuer;
    }

    /**
     * @return the reasonFlag
     */
    public ReasonFlag getReasonFlag() {
        return reasonFlag;
    }

    /**
     * @param reasonFlag
     *            the reasonFlag to set
     */
    public void setReasonFlag(final ReasonFlag reasonFlag) {
        this.reasonFlag = reasonFlag;
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
        result = prime * result + ((cRLIssuer == null) ? 0 : cRLIssuer.hashCode());
        result = prime * result + ((distributionPointName == null) ? 0 : distributionPointName.hashCode());
        result = prime * result + ((reasonFlag == null) ? 0 : reasonFlag.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CRLDistributionPoint [" + ((null == distributionPointName) ? "" : ("distributionPointName=" + distributionPointName)) + ((null == cRLIssuer) ? "" : (", cRLIssuer=" + cRLIssuer))
                + ((null == reasonFlag) ? "" : (", reasonFlag=" + reasonFlag)) + "]";
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
        final DistributionPoint other = (DistributionPoint) obj;
        if (cRLIssuer == null) {
            if (other.cRLIssuer != null) {
                return false;
            }
        } else if (!cRLIssuer.equals(other.cRLIssuer)) {
            return false;
        }
        if (distributionPointName == null) {
            if (other.distributionPointName != null) {
                return false;
            }
        } else if (!distributionPointName.equals(other.distributionPointName)) {
            return false;
        }
        if (reasonFlag != other.reasonFlag) {
            return false;
        }
        return true;
    }

}
