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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.*;
import javax.validation.constraints.Size;

@MappedSuperclass
public abstract class AbstractProfileData implements Serializable {

    private static final long serialVersionUID = -3288882274201197481L;

    @Id
    @SequenceGenerator(name = "SEQ_PROFILE_ID_GENERATOR", sequenceName = "SEQ_PROFILE_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_PROFILE_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "Name", unique = true, nullable = false)
    @Size(max = 255)
    private String name;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    @Column(name = "modifiable", nullable = false)
    private boolean modifiable;

    @Column(name = "profile_validity", nullable = true)
    private Date profileValidity;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;

    /**
     * @return the createdDate
     */
    public Date getCreatedDate() {
        return createdDate;
    }

    /**
     * @param createdDate
     *            the createdDate to set
     */
    public void setCreatedDate(final Date createdDate) {
        this.createdDate = createdDate;
    }

    /**
     * @return the modifiedDate
     */
    public Date getModifiedDate() {
        return modifiedDate;
    }

    /**
     * @param modifiedDate
     *            the modifiedDate to set
     */
    public void setModifiedDate(final Date modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

    /**
     * Sets current timestamp to createdDate and modifiedDate before Persist of Trust/Certificate/Entity Profile in DB
     */
    @PrePersist
    protected void onCreate() {
        createdDate = new Date();
        modifiedDate = new Date();
    }

    /**
     * Sets current timestamp to modifiedDate before Update of Trust/Certificate/Entity Profile in DB
     */
    @PreUpdate
    protected void onUpdate() {
        modifiedDate = new Date();
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
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
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
     * @return the active
     */
    public boolean isModifiable() {
        return modifiable;
    }

    /**
     * @param active
     *            the active to set
     */
    public void setModifiable(final boolean modifiable) {
        this.modifiable = modifiable;
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
     * Returns a hash code value for the object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (active ? 1231 : 1237);
        result = prime * result + (modifiable ? 1231 : 1237);
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((profileValidity == null) ? 0 : profileValidity.hashCode());
        return result;
    }

    /**
     * Indicates whether the invoking object is "equal to" the parameterized object
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

        final AbstractProfileData other = (AbstractProfileData) obj;

        if (active != other.active) {
            return false;
        }
        if (modifiable != other.modifiable) {
            return false;
        }
        if (id != other.id) {
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
        return true;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "AbstractProfileData [id=" + id + ", " + (name != null ? "name=" + name + ", " : "") + "active=" + active + ", modifiable="
                + modifiable + ", " + (profileValidity != null ? "profileValidity=" + profileValidity : "") + "]";
    }

}
