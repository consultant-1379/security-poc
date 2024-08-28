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
 * This is a mandatory extension of a certificate profile. If the profile type is ROOT CA entity or sub-CA entity then key usage must contain KeyCertSign,cRLSign, digitalSignature as a mandatory
 * values. This extension is marked as critical. Changing the criticality of this extension is not allowed.
 * 
 * This class holds the supported {@link KeyUsageType}.
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="KeyUsage">
 *   &lt;complexContent>
 *     &lt;extension base="{}CertificateExtension">
 *       &lt;sequence>
 *         &lt;element name="KeyUsageType" type="{}KeyUsageType" maxOccurs="unbounded"/>
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
@XmlType(name = "KeyUsage", propOrder = { "supportedKeyUsageTypes" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class KeyUsage extends CertificateExtension implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = 7351541484671737036L;

    @XmlElement(name = "SupportedKeyUsageType", required = true)
    protected List<KeyUsageType> supportedKeyUsageTypes;

    public KeyUsage() {
        this.critical = true;
    }

    /**
     * Gets the value of the supportedKeyUsageTypes property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot. Therefore any modification you make to the returned list will be present inside the JAXB object. This is why there is
     * not a <CODE>set</CODE> method for the keyUsageType property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getSupportedKeyUsageTypes().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link KeyUsageType }
     * 
     * 
     */
    public List<KeyUsageType> getSupportedKeyUsageTypes() {
        if (supportedKeyUsageTypes == null) {
            supportedKeyUsageTypes = new ArrayList<KeyUsageType>();
        }
        return this.supportedKeyUsageTypes;
    }

    /**
     * Sets the value of the supportedKeyUsageTypes property.
     * 
     * @param keyUsageType
     *            the supportedKeyUsageTypes to set
     */
    public void setSupportedKeyUsageTypes(final List<KeyUsageType> supportedKeyUsageTypes) {
        this.supportedKeyUsageTypes = supportedKeyUsageTypes;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " Key Usage: [ iscritical: " + critical + " keyUsageType: " + supportedKeyUsageTypes + " ] ";
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
        result = prime * result + ((supportedKeyUsageTypes == null) ? 0 : supportedKeyUsageTypes.hashCode());
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
        final KeyUsage other = (KeyUsage) obj;
        if (supportedKeyUsageTypes == null) {
            if (other.supportedKeyUsageTypes != null) {
                return false;
            }
        } else if (supportedKeyUsageTypes != null && other.supportedKeyUsageTypes == null) {
            return false;
        } else if (supportedKeyUsageTypes.size() != other.supportedKeyUsageTypes.size()) {
            return false;
        } else if (supportedKeyUsageTypes != null && other.supportedKeyUsageTypes != null) {
            boolean isMatched = false;
            for (final KeyUsageType keyUsageType : supportedKeyUsageTypes) {
                for (final KeyUsageType keyUsageTypeOther : other.supportedKeyUsageTypes) {
                    if (keyUsageType.equals(keyUsageTypeOther)) {
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
