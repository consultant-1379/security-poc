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
 * This extension indicates one or more purposes for which the certified public key may be used, in addition to or in place of the basic purposes indicated in the key usage extension. This extension
 * is applicable only for entity type.
 * 
 * This class holds the list of supported {@link KeyPurposeId} enum.
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="ExtendedKeyUsage">
 *   &lt;complexContent>
 *     &lt;extension base="{}CertificateExtension">
 *       &lt;sequence>
 *         &lt;element name="SupportedKeyPurposeId" type="{}KeyPurposeId" maxOccurs="unbounded"/>
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
@XmlType(name = "ExtendedKeyUsage", propOrder = { "supportedKeyPurposeIds" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class ExtendedKeyUsage extends CertificateExtension implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -5599467949832520029L;

    @XmlElement(name = "SupportedKeyPurposeId", required = true)
    protected List<KeyPurposeId> supportedKeyPurposeIds;

    /**
     * Gets the value of the Supported key Purpose Ids property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot. Therefore any modification you make to the returned list will be present inside the JAXB object. This is why there is
     * not a <CODE>set</CODE> method for the keyPurposeId property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getSupportedKeyPurposeIds().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link KeyPurposeId }
     * 
     * 
     */
    public List<KeyPurposeId> getSupportedKeyPurposeIds() {
        if (supportedKeyPurposeIds == null) {
            supportedKeyPurposeIds = new ArrayList<KeyPurposeId>();
        }
        return this.supportedKeyPurposeIds;
    }

    /**
     * Sets the value of the supportedkeyPurposeIds property.
     * 
     * @param keyPurposeId
     *            the keyPurposeId to set
     */
    public void setSupportedKeyPurposeIds(final List<KeyPurposeId> supportedKeyPurposeIds) {
        this.supportedKeyPurposeIds = supportedKeyPurposeIds;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " ExtendedKeyUsage: [ isCritical: " + critical + " supportedKeyPurposeIds: " + supportedKeyPurposeIds + " ] ";
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
        result = prime * result + ((supportedKeyPurposeIds == null) ? 0 : supportedKeyPurposeIds.hashCode());
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
        final ExtendedKeyUsage other = (ExtendedKeyUsage) obj;
        if (supportedKeyPurposeIds == null) {
            if (other.supportedKeyPurposeIds != null) {
                return false;
            }
        } else if (supportedKeyPurposeIds != null && other.supportedKeyPurposeIds == null) {
            return false;
        } else if (supportedKeyPurposeIds.size() != other.supportedKeyPurposeIds.size()) {
            return false;
        } else if (supportedKeyPurposeIds != null && other.supportedKeyPurposeIds != null) {
            boolean isMatched = false;
            for (final KeyPurposeId keyPurposeId : supportedKeyPurposeIds) {
                for (final KeyPurposeId keyPurposeIdOther : other.supportedKeyPurposeIds) {
                    if (keyPurposeId.equals(keyPurposeIdOther)) {
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
