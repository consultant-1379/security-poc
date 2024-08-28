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
package com.ericsson.oss.itpf.security.pki.manager.model.profiles;

import java.io.Serializable;
import java.util.Date;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;

/**
 * <p>
 * This is a abstract class for all profiles. It holds common attributes shared between all the profiles.
 *
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 *
 * <pre>
 * &lt;complexType name="AbstractProfile">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *       &lt;element name="ProfileValidity" type="{http://www.w3.org/2001/XMLSchema}date" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Name" use="required" type="{}nonEmptyString" />
 *       &lt;:attribute name="Id" type="xs:positiveInteger" use="optional" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AbstractProfile", propOrder = { "active", "profileValidity", "modifiable" })
@XmlSeeAlso({ EntityProfile.class, CertificateProfile.class, TrustProfile.class })
public abstract class AbstractProfile implements Serializable {

    /**
         *
         */
    private static final long serialVersionUID = 1611319345743730727L;
    @XmlAttribute(name = "Id", required = false)
    protected long id;
    @XmlAttribute(name = "Name", required = true)
    protected String name;
    @XmlElement(name = "ProfileValidity", required = false)
    protected Date profileValidity;
    @XmlElement(name = "Active", required = false)
    protected boolean active = true;
    @XmlElement(name = "Modifiable", required = false)
    protected boolean modifiable = true;

    @XmlTransient
    protected ProfileType type;

    /**
     * @return the profileType
     */
    public ProfileType getType() {
        return type;
    }

    /**
     * @param profileType
     *            the profileType to set
     */
    public void setType(final ProfileType type) {
        this.type = type;
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
     * @return the profileValidity
     */
    public Date getProfileValidity() {
        return profileValidity;
    }

    /**
     * @param profileValidity
     *            the profileValidity to set
     */
    public void setProfileValidity(final Date profileValidity) {
        this.profileValidity = profileValidity;
    }

    /**
     * @return the active
     */
    public boolean isActive() {
        return active;
    }

    /**
     * @param active
     *            the active to set
     */
    public void setActive(final boolean active) {
        this.active = active;
    }

    /**
     * @param modifiable
     *            the modifiable to set
     */
    public void setModifiable(final boolean modifiable) {
        this.modifiable = modifiable;
    }

    /**
     * @return the modifiable
     */
    public boolean isModifiable() {
        return modifiable;
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
        result = prime * result + (active ? 1231 : 1237);
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + (modifiable ? 1231 : 1237);
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((profileValidity == null) ? 0 : profileValidity.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
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
        final AbstractProfile other = (AbstractProfile) obj;
        if (active != other.active) {
            return false;
        }
        if (modifiable != other.modifiable) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (profileValidity == null) {
            if (other.profileValidity != null) {
                return false;
            }
        } else if (!profileValidity.equals(other.profileValidity)) {
            return false;
        }
        if (type != other.type) {
            return false;
        }
        return true;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "AbstractProfile [id=" + id + ", name=" + name + ((null == profileValidity) ? "" : (", profileValidity=" + profileValidity))
                + ", active=" + active + ", modifiable=" + modifiable + ", type=" + type;
    }
}
