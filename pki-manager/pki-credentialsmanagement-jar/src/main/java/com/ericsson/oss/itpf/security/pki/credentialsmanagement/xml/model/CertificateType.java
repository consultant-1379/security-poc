/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.credentialsmanagement.xml.model;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

/**
 * <p>
 * Java class for CertificateType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="overlapperiod" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="tbscertificate" type="{}TBSCertificateType"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="endentityprofilename" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="keypair" type="{}KeypairType"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="keystore" type="{}KeyStoreType"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="truststore" type="{}TrustStoreType"  minOccurs="1" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateType", propOrder = { "overlapPeriod", "tbsCertificate", "endEntityProfileName", "keyPair", "keyStore", "trustStore" })
public class CertificateType {
    @XmlElement(name = "overlapperiod", required = true)
    protected String overlapPeriod;
    @XmlElement(name = "tbscertificate", required = true)
    protected TBSCertificateType tbsCertificate;
    @XmlElement(name = "endentityprofilename", required = true)
    protected String endEntityProfileName;
    @XmlElement(name = "keypair", required = true)
    protected KeyPairType keyPair;
    @XmlElement(name = "keystore", required = true)
    protected List<KeyStoreType> keyStore;
    @XmlElement(name = "truststore", required = true)
    protected List<TrustStoreType> trustStore;

    /**
     * @return TBSCertificateType
     */
    public TBSCertificateType getTbsCertificate() {
        return tbsCertificate;
    }

    /**
     * @param TBSCertificateType
     *            the TBSCertificateType to set
     */
    public void setTbsCertificate(final TBSCertificateType value) {
        this.tbsCertificate = value;
    }

    /**
     * @return endEntityProfileName
     */
    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    /**
     * @param endentityprofilename
     *            the endEntityProfileName to be set.
     */
    public void setEndEntityProfileName(final String value) {
        this.endEntityProfileName = value;
    }

    /**
     * @return KeyPairType
     */
    public KeyPairType getKeyPair() {
        return keyPair;
    }

    /**
     * @param value
     *            the keyPair to set
     */
    public void setKeyPair(final KeyPairType value) {
        this.keyPair = value;
    }

    /**
     * @return List<KeyStoreType>
     */
    public List<KeyStoreType> getKeyStore() {
        if (keyStore == null) {
            keyStore = new ArrayList<>();
        }
        return this.keyStore;
    }

    /**
     * @param value
     *            the keyStore to set
     */
    public void setKeyStore(final List<KeyStoreType> value) {
        this.keyStore = value;
    }

    public List<TrustStoreType> getTrustStore() {
        if (trustStore == null) {
            trustStore = new ArrayList<>();
        }
        return this.trustStore;
    }

    /**
     * @param value
     *            the trustStore to set
     */
    public void setTrustStore(final List<TrustStoreType> value) {
        this.trustStore = value;
    }

    /**
     * @return the overlapPeriod
     */
    public String getOverlapPeriod() {
        return overlapPeriod;
    }

    /**
     * @param value
     *            the overlapPeriod to set
     */
    public void setOverlapPeriod(final String value) {
        this.overlapPeriod = value;
    }

}