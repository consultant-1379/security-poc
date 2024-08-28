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
 * The authority information access extension indicates how to access information and services for the issuer of the certificate in which the extension appears. This class contains list of access
 * descriptors.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="AuthorityInformationAccess">
 *   &lt;complexContent>
 *     &lt;extension base="{}CertificateExtension">
 *       &lt;sequence>
 *         &lt;element name="AccessDescription" type="{}AccessDescription" maxOccurs="unbounded"/>
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
@XmlType(name = "AuthorityInformationAccess", propOrder = { "accessDescriptions" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class AuthorityInformationAccess extends CertificateExtension implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -2250912776944362600L;

    @XmlElement(name = "AccessDescription", required = true)
    protected List<AccessDescription> accessDescriptions = new ArrayList<AccessDescription>();

    /**
     * @return the accessDescription
     */
    public List<AccessDescription> getAccessDescriptions() {
        return accessDescriptions;
    }

    /**
     * @param accessDescription
     *            the accessDescription to set
     */
    public void setAccessDescriptions(final List<AccessDescription> accessDescriptions) {
        this.accessDescriptions = accessDescriptions;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " AuthorityInformationAccess: [ isCritical: " + critical + " AccessDescriptions: " + accessDescriptions + " ] ";
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
        result = prime * result + ((accessDescriptions == null) ? 0 : accessDescriptions.hashCode());
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
        final AuthorityInformationAccess other = (AuthorityInformationAccess) obj;
        if (accessDescriptions == null) {
            if (other.accessDescriptions != null) {
                return false;
            }
        } else if (other.accessDescriptions == null) {
            if (accessDescriptions != null) {
                return false;
            }
        } else if (accessDescriptions != null && other.accessDescriptions != null) {
            if (accessDescriptions.size() != other.accessDescriptions.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final AccessDescription accessDescription : accessDescriptions) {
                for (final AccessDescription accessDescriptionOther : other.accessDescriptions) {
                    if (accessDescription.equals(accessDescriptionOther)) {
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
