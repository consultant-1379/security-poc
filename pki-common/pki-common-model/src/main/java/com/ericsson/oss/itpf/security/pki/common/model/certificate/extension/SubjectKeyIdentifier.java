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
 * The subject key identifier extension provides a means of identifying certificates that contain a particular public key. This extension is mandatory for ROOT CA and sub-CA type profile.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="SubjectKeyIdentifier">
 *   &lt;complexContent>
 *     &lt;extension base="{}CertificateExtension">
 *       &lt;sequence>
 *         &lt;element name="KeyIdentifier" type="{}KeyIdentifier"/>
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
@XmlType(name = "SubjectKeyIdentifier", propOrder = { "keyIdentifier" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class SubjectKeyIdentifier extends CertificateExtension implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -5957736622585327343L;

    @XmlElement(name = "KeyIdentifier", required = true)
    protected KeyIdentifier keyIdentifier;

    /**
     * @return the keyIdentifier
     */
    public KeyIdentifier getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * @param keyIdentifier
     *            the keyIdentifier to set
     */
    public void setKeyIdentifier(final KeyIdentifier keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "SubjectKeyIdentifier [keyIdentifier=" + keyIdentifier + "]";
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
        result = prime * result + ((keyIdentifier == null) ? 0 : keyIdentifier.hashCode());
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
        final SubjectKeyIdentifier other = (SubjectKeyIdentifier) obj;
        if (keyIdentifier == null) {
            if (other.keyIdentifier != null) {
                return false;
            }
        } else if (!keyIdentifier.equals(other.keyIdentifier)) {
            return false;
        }
        return true;
    }
}
