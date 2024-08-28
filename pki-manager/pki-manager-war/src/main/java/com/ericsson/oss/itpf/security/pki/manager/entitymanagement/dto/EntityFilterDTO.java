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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto;

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * <p>
 * This class contains filter conditions based on which entities has to be filtered.
 * </p>
 */
public class EntityFilterDTO implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 1437415625720036474L;

    protected List<EntityType> type;
    protected String name;
    protected Integer certificateAssigned;
    protected List<EntityStatus> status;

    /**
     * @return the entityTypes
     */
    public List<EntityType> getType() {
        return type;
    }

    /**
     * @param entityTypes
     *            the entityTypes to set
     */
    public void setType(final List<EntityType> type) {
        this.type = type;
    }

    /**
     * @return the entityName
     */
    public String getName() {
        return name;
    }

    /**
     * @param entityName
     *            the entityName to set
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * @return the certificateAssigned
     */
    public Integer getCertificateAssigned() {
        return certificateAssigned;
    }

    /**
     * @param certificateAssigned
     *            the certificateAssigned to set
     */
    public void setCertificateAssigned(final Integer certificateAssigned) {
        this.certificateAssigned = certificateAssigned;
    }

    /**
     * @return the status
     */
    public List<EntityStatus> getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final List<EntityStatus> status) {
        this.status = status;
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

        result = prime * result + certificateAssigned;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());

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
        final EntityFilterDTO other = (EntityFilterDTO) obj;
        if (certificateAssigned != other.certificateAssigned) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (type == null) {
            if (other.type != null) {
                return false;
            }
        } else if (!type.equals(other.type)) {
            return false;
        }
        if (status == null) {
            if (other.status != null) {
                return false;
            }
        } else if (!status.equals(other.status)) {
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
        return "FilterDTO [entityTypes=" + type + ", entityName=" + name + ", certificateAssigned=" + certificateAssigned + ", status=" + status + "]";
    }
}
