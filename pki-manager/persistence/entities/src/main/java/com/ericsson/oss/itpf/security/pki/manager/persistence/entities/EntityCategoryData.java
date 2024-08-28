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

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
@Table(name = "entity_category", uniqueConstraints = @UniqueConstraint(columnNames = { "name" }))
public class EntityCategoryData implements Serializable {

    private static final long serialVersionUID = -7471226606573256421L;

    @Id
    @SequenceGenerator(name = "SEQ_ENTITY_CATEGORY_ID_GENERATOR", sequenceName = "SEQ_ENTITY_CATEGORY_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_ENTITY_CATEGORY_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "Name", unique = true, nullable = false)
    @Size(max = 255)
    private String name;

    @Column(name = "modifiable", nullable = false)
    private boolean modifiable = true;

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
     * @return the modifiable
     */
    public boolean isModifiable() {
        return modifiable;
    }

    /**
     * @param modifiable
     *            the modifiable to set
     */
    public void setModifiable(final boolean modifiable) {
        this.modifiable = modifiable;
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
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + (modifiable ? 1231 : 1237);
        result = prime * result + ((name == null) ? 0 : name.hashCode());
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

        final EntityCategoryData other = (EntityCategoryData) obj;

        if (id != other.id) {
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
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "EntityCategoryData [id=" + id + ", " + (name != null ? "name=" + name + ", " : "") + "modifiable=" + modifiable + "]";
    }

}
