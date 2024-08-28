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

import javax.xml.bind.annotation.*;

/**
 * <p>
 * Java class for ApplicationType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ApplicationType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="certificates" type="{}CertificatesType"  minOccurs="1" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ApplicationType", propOrder = { "certificates" })
public class ApplicationType {

    @XmlElement(name = "certificates", required = true)
    protected CertificatesType certificates;

    /**
     * @return CertificatesType
     */
    public CertificatesType getCertificates() {
        return certificates;
    }

    /**
     * @param CertificatesType
     *            the CertificatesType to set
     */
    public void setCertificates(final CertificatesType value) {
        this.certificates = value;
    }

}
