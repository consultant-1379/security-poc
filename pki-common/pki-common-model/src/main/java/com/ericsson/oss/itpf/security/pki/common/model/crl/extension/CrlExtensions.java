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

import javax.xml.bind.annotation.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityInformationAccess;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * This is wrapper class holding list of CRL extensions.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CrlExtensions">
 *      &lt;sequence>
 *              &lt;element name="crlNumber" type="CRLNumber"
 *                              minOccurs="0" />
 *              &lt;element name="AuthorityInformationAccess" type="AuthorityInformationAccess"
 *                              minOccurs="0" />
 *              &lt;element name="AuthorityKeyIdentifier" type="AuthorityKeyIdentifier"
 *                               minOccurs="0" />
 *              &lt;element name="IssuingDistributionPoint" type="IssuingDistributionPoint"
 *                               minOccurs="0" />        
 *       &lt;/sequence>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CrlExtensions", propOrder = { "crlNumber", "authorityInformationAccess", "authorityKeyIdentifier", "issuingDistributionPoint" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class CrlExtensions implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 7122326644813228722L;

    @XmlElement(name = "CRLNumber", required = false)
    protected CRLNumber crlNumber;

    @XmlElement(name = "AuthorityInformationAccess", required = false)
    protected AuthorityInformationAccess authorityInformationAccess;

    @XmlElement(name = "AuthorityKeyIdentifier", required = false)
    protected AuthorityKeyIdentifier authorityKeyIdentifier;

    @XmlElement(name = "IssuingDistributionPoint", required = false)
    protected IssuingDistributionPoint issuingDistributionPoint;

    /**
     * @return the crlNumber
     */
    public CRLNumber getCrlNumber() {
        return crlNumber;
    }

    /**
     * @param crlNumber
     *            the crlNumber to set
     */
    public void setCrlNumber(final CRLNumber crlNumber) {
        this.crlNumber = crlNumber;
    }

    /**
     * @return the authorityInformationAccess
     */
    public AuthorityInformationAccess getAuthorityInformationAccess() {
        return authorityInformationAccess;
    }

    /**
     * @param authorityInformationAccess
     *            the authorityInformationAccess to set
     */
    public void setAuthorityInformationAccess(final AuthorityInformationAccess authorityInformationAccess) {
        this.authorityInformationAccess = authorityInformationAccess;
    }

    /**
     * @return the authorityKeyIdentifier
     */
    public AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    /**
     * @param authorityKeyIdentifier
     *            the authorityKeyIdentifier to set
     */
    public void setAuthorityKeyIdentifier(final AuthorityKeyIdentifier authorityKeyIdentifier) {
        this.authorityKeyIdentifier = authorityKeyIdentifier;
    }

    /**
     * @return the issuingDistributionPoint
     */
    public IssuingDistributionPoint getIssuingDistributionPoint() {
        return issuingDistributionPoint;
    }

    /**
     * @param issuingDistributionPoint
     *            the issuingDistributionPoint to set
     */
    public void setIssuingDistributionPoint(final IssuingDistributionPoint issuingDistributionPoint) {
        this.issuingDistributionPoint = issuingDistributionPoint;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((authorityInformationAccess == null) ? 0 : authorityInformationAccess.hashCode());
        result = prime * result + ((authorityKeyIdentifier == null) ? 0 : authorityKeyIdentifier.hashCode());
        result = prime * result + ((crlNumber == null) ? 0 : crlNumber.hashCode());
        result = prime * result + ((issuingDistributionPoint == null) ? 0 : issuingDistributionPoint.hashCode());
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
        final CrlExtensions other = (CrlExtensions) obj;
        if (authorityInformationAccess == null) {
            if (other.authorityInformationAccess != null) {
                return false;
            }
        } else if (!authorityInformationAccess.equals(other.authorityInformationAccess)) {
            return false;
        }
        if (authorityKeyIdentifier == null) {
            if (other.authorityKeyIdentifier != null) {
                return false;
            }
        } else if (!authorityKeyIdentifier.equals(other.authorityKeyIdentifier)) {
            return false;
        }
        if (crlNumber == null) {
            if (other.crlNumber != null) {
                return false;
            }
        } else if (!crlNumber.equals(other.crlNumber)) {
            return false;
        }
        if (issuingDistributionPoint == null) {
            if (other.issuingDistributionPoint != null) {
                return false;
            }
        } else if (!issuingDistributionPoint.equals(other.issuingDistributionPoint)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "CrlExtensions [crlNumber=" + crlNumber + ", authorityInformationAccess=" + authorityInformationAccess + ", authorityKeyIdentifier=" + authorityKeyIdentifier
                + ", issuingDistributionPoint=" + issuingDistributionPoint + "]";
    }

}
