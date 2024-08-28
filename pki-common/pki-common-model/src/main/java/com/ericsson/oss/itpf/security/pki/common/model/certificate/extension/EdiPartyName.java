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
 * This class represents the ASN.1 structure of EDIPartyName which can be accepted as one of the values for Subject Alternative Name.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class
 * 
 * <pre>
 * &lt;complexType name="EdiPartyName">
 *   &lt;complexContent>
 *     &lt;extension base="{}AbstractSubjectAltNameFieldValue">
 *       &lt;sequence>
 *         &lt;element name="NameAssigner" type="{}nonEmptyString"/>
 *         &lt;element name="PartyName" type="{}nonEmptyString"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EdiPartyName", propOrder = { "nameAssigner", "partyName" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class EdiPartyName extends AbstractSubjectAltNameFieldValue implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = 869117501615076120L;
    @XmlElement(name = "NameAssigner", required = true)
    protected String nameAssigner;
    @XmlElement(name = "PartyName", required = true)
    protected String partyName;

    /**
     * Gets the value of the nameAssigner property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getNameAssigner() {
        return nameAssigner;
    }

    /**
     * Sets the value of the nameAssigner property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setNameAssigner(final String value) {
        this.nameAssigner = value;
    }

    /**
     * Gets the value of the partyName property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getPartyName() {
        return partyName;
    }

    /**
     * Sets the value of the partyName property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setPartyName(final String value) {
        this.partyName = value;
    }

    @Override
    public String toString() {
        return " [ nameAssigner: " + nameAssigner + " partyName: " + partyName + " ] ";
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
        result = prime * result + ((nameAssigner == null) ? 0 : nameAssigner.hashCode());
        result = prime * result + ((partyName == null) ? 0 : partyName.hashCode());
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
        final EdiPartyName other = (EdiPartyName) obj;
        if (nameAssigner == null) {
            if (other.nameAssigner != null) {
                return false;
            }
        } else if (!nameAssigner.equals(other.nameAssigner)) {
            return false;
        }
        if (partyName == null) {
            if (other.partyName != null) {
                return false;
            }
        } else if (!partyName.equals(other.partyName)) {
            return false;
        }
        return true;
    }

}
