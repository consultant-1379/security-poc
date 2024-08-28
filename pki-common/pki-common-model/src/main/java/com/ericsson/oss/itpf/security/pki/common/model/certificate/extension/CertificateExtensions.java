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
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * This is wrapper class holding list of certificate extensions.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateExtensions">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="CertificateExtension" type="{}CertificateExtension" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateExtensions", propOrder = { "certificateExtensions" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class CertificateExtensions implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 7122326644813228722L;
    @XmlElement(name = "CertificateExtension", required = true)
    protected List<CertificateExtension> certificateExtensions = new ArrayList<CertificateExtension>();

    /**
     * @return the certificateExtension
     */
    public List<CertificateExtension> getCertificateExtensions() {
        return certificateExtensions;
    }

    /**
     * @param certificateExtension
     *            the certificateExtension to set
     */
    public void setCertificateExtensions(final List<CertificateExtension> certificateExtensions) {
        this.certificateExtensions = certificateExtensions;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {

        return certificateExtensions.toString();
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
        result = prime * result + ((certificateExtensions == null) ? 0 : certificateExtensions.hashCode());
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
        final CertificateExtensions other = (CertificateExtensions) obj;
        if (certificateExtensions == null) {
            if (other.certificateExtensions != null) {
                return false;
            }
        } else if (certificateExtensions.size() != other.certificateExtensions.size()) {
            return false;
        } else if (certificateExtensions != null && other.certificateExtensions != null) {
            boolean isMatched = false;
            for (final CertificateExtension certificateExtension : certificateExtensions) {
                for (final CertificateExtension certificateExtensionOther : other.certificateExtensions) {
                    if (certificateExtension.getClass() == certificateExtensionOther.getClass() && certificateExtension.equals(certificateExtensionOther)) {
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
