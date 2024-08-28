/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

import org.bouncycastle.asn1.x509.AuthorityInformationAccess;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "certificateExtensions", propOrder = { "subjectAltName", "keyUsage", "basicConstraints", "authorityKeyIdentifier",
        "subjectKeyIdentifier", "authorityInformationAccess", "extendedKeyUsage", "crlDistributionPoints" })
public class CredentialManagerCertificateExtensions implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -9165332315836313066L;
    /**
     *
     */

    //protected CredentialManagerSubjectAltNameFlags subjectAltName;
    @XmlElement(required = true)
    protected CredentialManagerKeyUsage keyUsage;
    protected CredentialManagerBasicConstraints basicConstraints;
    protected CredentialManagerAuthorityKeyIdentifier authorityKeyIdentifier;
    protected CredentialManagerSubjectKeyIdentifier subjectKeyIdentifier;
    protected CredentialManagerAuthorityInformationAccess authorityInformationAccess;
    protected CredentialManagerExtendedKeyUsage extendedKeyUsage;
    protected CredentialManagerCRLDistributionPoints crlDistributionPoints;

    /**
     * Gets the value of the subjectAltName property.
     * 
     * @return possible object is {@link SubjectAltNameFlags }
     * 
     */
    //    public CredentialManagerSubjectAltNameFlags getSubjectAltName() {
    //        return subjectAltName;
    //    }

    /**
     * Sets the value of the subjectAltName property.
     * 
     * @param value
     *            allowed object is {@link SubjectAltNameFlags }
     * 
     */
    //    public void setSubjectAltName(final CredentialManagerSubjectAltNameFlags value) {
    //        this.subjectAltName = value;
    //    }

    /**
     * Gets the value of the keyUsage property.
     * 
     * @return possible object is {@link KeyUsage }
     * 
     */
    public CredentialManagerKeyUsage getKeyUsage() {
        return keyUsage;
    }

    /**
     * Sets the value of the keyUsage property.
     * 
     * @param value
     *            allowed object is {@link KeyUsage }
     * 
     */
    public void setKeyUsage(final CredentialManagerKeyUsage value) {
        this.keyUsage = value;
    }

    /**
     * Gets the value of the basicConstraints property.
     * 
     * @return possible object is {@link BasicConstraints }
     * 
     */
    public CredentialManagerBasicConstraints getBasicConstraints() {
        return basicConstraints;
    }

    /**
     * Sets the value of the basicConstraints property.
     * 
     * @param value
     *            allowed object is {@link BasicConstraints }
     * 
     */
    public void setBasicConstraints(final CredentialManagerBasicConstraints value) {
        this.basicConstraints = value;
    }

    /**
     * Gets the value of the authorityKeyIdentifier property.
     * 
     * @return possible object is {@link AuthorityKeyIdentifier }
     * 
     */
    public CredentialManagerAuthorityKeyIdentifier getAuthorityKeyIdentifier() {
        return authorityKeyIdentifier;
    }

    /**
     * Sets the value of the authorityKeyIdentifier property.
     * 
     * @param value
     *            allowed object is {@link AuthorityKeyIdentifier }
     * 
     */
    public void setAuthorityKeyIdentifier(final CredentialManagerAuthorityKeyIdentifier value) {
        this.authorityKeyIdentifier = value;
    }

    /**
     * Gets the value of the subjectKeyIdentifier property.
     * 
     * @return possible object is {@link Boolean }
     * 
     */
    public CredentialManagerSubjectKeyIdentifier getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    /**
     * Sets the value of the subjectKeyIdentifier property.
     * 
     * @param value
     *            allowed object is {@link Boolean }
     * 
     */
    public void setSubjectKeyIdentifier(final CredentialManagerSubjectKeyIdentifier value) {
        this.subjectKeyIdentifier = value;
    }

    /**
     * Gets the value of the authorityInformationAccess property.
     * 
     * @return possible object is {@link AuthorityInformationAccess }
     * 
     */
    public CredentialManagerAuthorityInformationAccess getAuthorityInformationAccess() {
        return authorityInformationAccess;
    }

    /**
     * Sets the value of the authorityInformationAccess property.
     * 
     * @param value
     *            allowed object is {@link AuthorityInformationAccess }
     * 
     */
    public void setAuthorityInformationAccess(final CredentialManagerAuthorityInformationAccess value) {
        this.authorityInformationAccess = value;
    }

    /**
     * Gets the value of the extendedKeyUsage property.
     * 
     * @return possible object is {@link ExtendedKeyUsage }
     * 
     */
    public CredentialManagerExtendedKeyUsage getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    /**
     * Sets the value of the extendedKeyUsage property.
     * 
     * @param value
     *            allowed object is {@link ExtendedKeyUsage }
     * 
     */
    public void setExtendedKeyUsage(final CredentialManagerExtendedKeyUsage value) {
        this.extendedKeyUsage = value;
    }

    /**
     * Gets the value of the crlDistributionPoint property.
     * 
     * @return possible object is {@link CrlDistributionPoint }
     * 
     */
    public CredentialManagerCRLDistributionPoints getCrlDistributionPoints() {
        return crlDistributionPoints;
    }

    /**
     * Sets the value of the crlDistributionPoint property.
     * 
     * @param value
     *            allowed object is {@link CrlDistributionPoint }
     * 
     */
    public void setCrlDistributionPoints(final CredentialManagerCRLDistributionPoints value) {
        this.crlDistributionPoints = value;
    }

    @Override
    public String toString() {
        final StringBuffer buffer = new StringBuffer();
        buffer.append(" keyUsage: " + keyUsage);
        buffer.append(" basicConstraints: " + basicConstraints);
        buffer.append(" authorityKeyIdentifier: " + authorityKeyIdentifier);
        buffer.append(" subjectKeyIdentifier: " + subjectKeyIdentifier);
        //buffer.append(" subjectAltName: " + subjectAltName);
        buffer.append(" authorityInformationAccess: " + authorityInformationAccess);
        buffer.append(" extendedKeyUsage: " + extendedKeyUsage);
        buffer.append(" crlDistributionPoint: " + crlDistributionPoints);
        return buffer.toString();
    }
}
