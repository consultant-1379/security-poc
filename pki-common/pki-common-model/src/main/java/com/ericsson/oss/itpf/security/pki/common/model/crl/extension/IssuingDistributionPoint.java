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
import java.util.List;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * IssuingDistributionPoint CRL extension contains List of Issuing Distribution Points.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="IssuingDistributionPoint">
 *       &lt;sequence>
 *              &lt;element name="Critical" type="xs:boolean" minOccurs="1" />
 *              &lt;element name="OnlyContainsUserCerts" type="xs:boolean"
 *                               minOccurs="1" />
 *              &lt;element name="OnlyContainsCACerts" type="xs:boolean"
 *                               minOccurs="1" />
 *              &lt;element name="OnlyContainsAttributeCerts" type="xs:boolean"
 *                               minOccurs="1" />
 *              &lt;element name="DistributionPoint" type="xs:boolean"
 *                               minOccurs="0" />
 *              &lt;element name="onlySomeReasons" type="ReasonFlag" minOccurs="0" unbounded=true/>
 *       &lt;/sequence>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "IssuingDistributionPoint", propOrder = { "critical", "onlyContainsUserCerts", "onlyContainsCACerts", "onlyContainsAttributeCerts", "distributionPoint",
        "onlySomeReasons" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class IssuingDistributionPoint implements Serializable {

    private static final long serialVersionUID = -5739589006460782189L;

    @XmlElement(name = "Critical", required = true)
    protected boolean critical;

    @XmlElement(name = "onlyContainsUserCerts", required = true)
    protected boolean onlyContainsUserCerts;

    @XmlElement(name = "onlyContainsCACerts", required = true)
    protected boolean onlyContainsCACerts;

    // Currently in PKI System, this field is not supported, So PKI system will not expect this field from XML while creating CA Entity with CRLGenerationInfo.
    protected static final boolean indirectCRL = false;

    @XmlElement(name = "OnlyContainsAttributeCerts", required = true)
    protected boolean onlyContainsAttributeCerts;

    @XmlElement(name = "DistributionPoint", required = false)
    protected DistributionPointName distributionPoint;

    @XmlElement(name = "OnlySomeReasons", required = false)
    protected List<ReasonFlag> onlySomeReasons;

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
     * @return the onlyContainsUserCerts
     */
    public boolean isOnlyContainsUserCerts() {
        return onlyContainsUserCerts;
    }

    /**
     * @param onlyContainsUserCerts
     *            the onlyContainsUserCerts to set
     */
    public void setOnlyContainsUserCerts(final boolean onlyContainsUserCerts) {
        this.onlyContainsUserCerts = onlyContainsUserCerts;
    }

    /**
     * @return the onlyContainsCACerts
     */
    public boolean isOnlyContainsCACerts() {
        return onlyContainsCACerts;
    }

    /**
     * @param onlyContainsCACerts
     *            the onlyContainsCACerts to set
     */
    public void setOnlyContainsCACerts(final boolean onlyContainsCACerts) {
        this.onlyContainsCACerts = onlyContainsCACerts;
    }

    /**
     * @return the onlyContainsAttributeCerts
     */
    public boolean isOnlyContainsAttributeCerts() {
        return onlyContainsAttributeCerts;
    }

    /**
     * @param onlyContainsAttributeCerts
     *            the onlyContainsAttributeCerts to set
     */
    public void setOnlyContainsAttributeCerts(final boolean onlyContainsAttributeCerts) {
        this.onlyContainsAttributeCerts = onlyContainsAttributeCerts;
    }

    /**
     * @return the distributionPoint
     */
    public DistributionPointName getDistributionPoint() {
        return distributionPoint;
    }

    /**
     * @param distributionPoint
     *            the distributionPoint to set
     */
    public void setDistributionPoint(final DistributionPointName distributionPoint) {
        this.distributionPoint = distributionPoint;
    }

    /**
     * @return the onlySomeReasons
     */
    public List<ReasonFlag> getOnlySomeReasons() {
        return onlySomeReasons;
    }

    /**
     * @param onlySomeReasons
     *            the onlySomeReasons to set
     */
    public void setOnlySomeReasons(final List<ReasonFlag> onlySomeReasons) {
        this.onlySomeReasons = onlySomeReasons;
    }

    /**
     * @return the indirectCRL
     */
    public boolean isIndirectCRL() {
        return indirectCRL;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (critical ? 1231 : 1237);
        result = prime * result + ((distributionPoint == null) ? 0 : distributionPoint.hashCode());
        result = prime * result + (indirectCRL ? 1231 : 1237);
        result = prime * result + (onlyContainsAttributeCerts ? 1231 : 1237);
        result = prime * result + (onlyContainsCACerts ? 1231 : 1237);
        result = prime * result + (onlyContainsUserCerts ? 1231 : 1237);
        result = prime * result + ((onlySomeReasons == null) ? 0 : onlySomeReasons.hashCode());
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

        final IssuingDistributionPoint other = (IssuingDistributionPoint) obj;
        if (critical != other.critical) {
            return false;
        }

        if (distributionPoint == null) {
            if (other.distributionPoint != null) {
                return false;
            }
        } else if (!distributionPoint.equals(other.distributionPoint)) {
            return false;
        }

        if (indirectCRL != other.indirectCRL) {
            return false;
        }

        if (onlyContainsAttributeCerts != other.onlyContainsAttributeCerts) {
            return false;
        }

        if (onlyContainsCACerts != other.onlyContainsCACerts) {
            return false;
        }

        if (onlyContainsUserCerts != other.onlyContainsUserCerts) {
            return false;
        }

        if (onlySomeReasons == null) {
            if (other.onlySomeReasons != null) {
                return false;
            }
        } else if (!onlySomeReasons.equals(other.onlySomeReasons)) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return "IssuingDistributionPoint [critical=" + critical + ", onlyContainsUserCerts=" + onlyContainsUserCerts + ", onlyContainsCACerts=" + onlyContainsCACerts + ", indirectCRL=" + indirectCRL
                + ", onlyContainsAttributeCerts=" + onlyContainsAttributeCerts + ", distributionPoint=" + distributionPoint + ", onlySomeReasons=" + onlySomeReasons + "]";
    }

}
