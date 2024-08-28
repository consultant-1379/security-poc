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

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;

public abstract class CredentialManagerAbstractEntity implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -8852377180841518342L;
    @XmlAttribute(name = "id", required = false)
    protected long id;
    @XmlAttribute(name = "name", required = true)
    protected String name;
    @XmlTransient
    protected CredentialManagerEntityType entityType;

    protected CredentialManagerEntityStatus entityStatus;
    @XmlElement(name = "subject", required = true)
    protected CredentialManagerSubject subject;
    @XmlElement(name = "subjectAltName")
    protected CredentialManagerSubjectAltName subjectAltName;
    @XmlElement(required = true)
    protected String entityProfileName;
    @XmlElement(name = "keyGenerationAlgorithm")
    protected CredentialManagerAlgorithm keyGenerationAlgorithm;
    @XmlElement(name = "issuerDN")
    protected CredentialManagerSubject issuerDN;

    /**
     * @return the entityType
     */
    public CredentialManagerEntityType getEntityType() {
        return entityType;
    }

    /**
     * @param entityType
     *            the entityType to set
     */
    public void setEntityType(final CredentialManagerEntityType entityType) {
        this.entityType = entityType;
    }

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
     * Gets the value of the name property.
     *
     * @return possible object is {@link String }
     *
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     *
     * @param value
     *            allowed object is {@link String }
     *
     */
    public void setName(final String value) {
        this.name = value;
    }

    /**
     * @return the entityStatus
     */
    public CredentialManagerEntityStatus getEntityStatus() {
        return entityStatus;
    }

    /**
     * @param entityStatus
     *            the entityStatus to set
     */
    public void setEntityStatus(final CredentialManagerEntityStatus entityStatus) {
        this.entityStatus = entityStatus;
    }

    /**
     * @return the subject
     */
    public CredentialManagerSubject getSubject() {
        return subject;
    }

    /**
     * @param subject
     *            the subject to set
     */
    public void setSubject(final CredentialManagerSubject subject) {
        this.subject = subject;
    }

    /**
     * @return the subjectAltName
     */
    public CredentialManagerSubjectAltName getSubjectAltName() {
        return subjectAltName;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public void setSubjectAltName(final CredentialManagerSubjectAltName subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    /**
     * @return the entityProfileName
     */
    public String getEntityProfileName() {
        return entityProfileName;
    }

    /**
     * @param entityProfileName
     *            the entityProfileName to set
     */
    public void setEntityProfileName(final String entityProfileName) {
        this.entityProfileName = entityProfileName;
    }

    /**
     * @return the keyGenerationAlgorithm
     */
    public CredentialManagerAlgorithm getKeyGenerationAlgorithm() {
        return keyGenerationAlgorithm;
    }

    /**
     * @param keyGenerationAlgorithm
     *            the keyGenerationAlgorithm to set
     */
    public void setKeyGenerationAlgorithm(final CredentialManagerAlgorithm keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
    }

    /**
     * @return the issuerDN
     */
    public CredentialManagerSubject getIssuerDN() {
        return issuerDN;
    }

    /**
     * @param issuerDN
     *            the issuerDN to set
     */
    public void setIssuerDN(final CredentialManagerSubject issuerDN) {
        this.issuerDN = issuerDN;
    }
}
