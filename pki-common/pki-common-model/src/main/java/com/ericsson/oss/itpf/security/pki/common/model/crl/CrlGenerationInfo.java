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
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;
import javax.xml.datatype.Duration;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;

/**
 * This class holds the information of CRL Generation Information. This is used in PKI Core and PKI Manager.
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="CrlGenerationInfo">
 *   &lt;complexContent>
 *    &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *          &lt;element name="Id" type="xs:positiveInteger" minOccurs="1" /> *       
 *          &lt;element name="SignatureAlgorithm" type="SignatureAlgorithm" minOccurs="1" />    
 *          &lt;element name="ValidityPeriod" type="xs:positiveInteger" minOccurs="1" />
 *          &lt;element name="SkewCrlTime" type="xs:positiveInteger" minOccurs="0" />
 *          &lt;element name="OverLapPeriod" type="xs:positiveInteger" minOccurs="0" />
 *          &lt;element name="Version" type="nonEmptyString" minOccurs="1" />
 *          &lt;element name="CaCertificate" type="Certificate" minOccurs="0" />
 *          &lt;element name="CrlExtensions" type="CrlExtensions" minOccurs="1" />
 *       &lt;/sequence>
 *    &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */

@XmlRootElement(name = "CrlGenerationInfo")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CrlGenerationInfo", propOrder = { "id", "signatureAlgorithm", "validityPeriod", "skewCrlTime", "overlapPeriod", "version", "caCertificates", "crlExtensions" })
public class CrlGenerationInfo implements Serializable {

    private static final long serialVersionUID = -2097786196924540286L;

    @XmlElement(name = "Id", required = false)
    @XmlSchemaType(name = "positiveInteger")
    protected long id;
    @XmlElement(name = "SignatureAlgorithm", required = true)
    protected Algorithm signatureAlgorithm;
    @XmlElement(name = "ValidityPeriod", required = true)
    protected Duration validityPeriod;
    @XmlElement(name = "SkewCrlTime", required = false)
    protected Duration skewCrlTime;
    @XmlElement(name = "OverlapPeriod", required = false)
    protected Duration overlapPeriod;
    @XmlElement(name = "Version", required = true)
    protected CRLVersion version;
    @XmlElement(name = "CaCertificates", required = false)
    protected List<Certificate> caCertificates = new ArrayList<Certificate>();
    @XmlElement(name = "CrlExtensions", required = false)
    protected CrlExtensions crlExtensions;

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
     * @return the signatureAlgorithm
     */
    public Algorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(final Algorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @return the validityPeriod
     */
    public Duration getValidityPeriod() {
        return validityPeriod;
    }

    /**
     * @param validityPeriod
     *            the validityPeriod to set
     */
    public void setValidityPeriod(final Duration validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    /**
     * @return the skewCrlTime
     */
    public Duration getSkewCrlTime() {
        return skewCrlTime;
    }

    /**
     * @param skewCrlTime
     *            the skewCrlTime to set
     */
    public void setSkewCrlTime(final Duration skewCrlTime) {
        this.skewCrlTime = skewCrlTime;
    }

    /**
     * @return the overLapPeriod
     */
    public Duration getOverlapPeriod() {
        return overlapPeriod;
    }

    /**
     * @param overlapPeriod
     *            the overLapPeriod to set
     */
    public void setOverlapPeriod(final Duration overlapPeriod) {
        this.overlapPeriod = overlapPeriod;
    }

    /**
     * @return the version
     */
    public CRLVersion getVersion() {
        return version;
    }

    /**
     * @param version
     *            the version to set
     */
    public void setVersion(final CRLVersion version) {
        this.version = version;
    }

    /**
     * @return the caCertificates
     */
    public List<Certificate> getCaCertificates() {
        return caCertificates;
    }

    /**
     * @param caCertificates
     *            the caCertificates to set
     */
    public void setCaCertificates(final List<Certificate> caCertificates) {
        this.caCertificates = caCertificates;
    }

    /**
     * @return the crlExtensions
     */
    public CrlExtensions getCrlExtensions() {
        return crlExtensions;
    }

    /**
     * @param crlExtensions
     *            the crlExtensions to set
     */
    public void setCrlExtensions(final CrlExtensions crlExtensions) {
        this.crlExtensions = crlExtensions;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caCertificates == null) ? 0 : caCertificates.hashCode());
        result = prime * result + ((crlExtensions == null) ? 0 : crlExtensions.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((overlapPeriod == null) ? 0 : overlapPeriod.hashCode());
        result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
        result = prime * result + ((skewCrlTime == null) ? 0 : skewCrlTime.hashCode());
        result = prime * result + ((validityPeriod == null) ? 0 : validityPeriod.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
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
        final CrlGenerationInfo other = (CrlGenerationInfo) obj;
        if (caCertificates == null) {
            if (other.caCertificates != null) {
                return false;
            }
        } else if (!caCertificates.equals(other.caCertificates)) {
            return false;
        }
        if (crlExtensions == null) {
            if (other.crlExtensions != null) {
                return false;
            }
        } else if (!crlExtensions.equals(other.crlExtensions)) {
            return false;
        }
        if (id != other.id) {
            return false;
        }
        if (overlapPeriod == null) {
            if (other.overlapPeriod != null) {
                return false;
            }
        } else if (!overlapPeriod.equals(other.overlapPeriod)) {
            return false;
        }
        if (signatureAlgorithm == null) {
            if (other.signatureAlgorithm != null) {
                return false;
            }
        } else if (!signatureAlgorithm.equals(other.signatureAlgorithm)) {
            return false;
        }
        if (skewCrlTime == null) {
            if (other.skewCrlTime != null) {
                return false;
            }
        } else if (!skewCrlTime.equals(other.skewCrlTime)) {
            return false;
        }
        if (validityPeriod == null) {
            if (other.validityPeriod != null) {
                return false;
            }
        } else if (!validityPeriod.equals(other.validityPeriod)) {
            return false;
        }
        if (version != other.version) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "CrlGenerationInfo [id=" + id + ", signatureAlgorithm=" + signatureAlgorithm + ", validityPeriod=" + validityPeriod + ", skewCrlTime=" + skewCrlTime + ", overLapPeriod="
                + overlapPeriod + ", version=" + version + ", caCertificates=" + caCertificates + ", crlExtensions=" + crlExtensions + "]";
    }

}
