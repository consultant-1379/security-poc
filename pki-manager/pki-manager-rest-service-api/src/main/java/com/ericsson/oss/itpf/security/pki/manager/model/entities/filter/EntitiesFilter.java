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
package com.ericsson.oss.itpf.security.pki.manager.model.entities.filter;

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * <p>
 * This class specifies the filter conditions, offset and limit based on which {@link Entity} / {@link CAEntity} has to be fetched
 * </p>
 * 
 * @author tcspred
 * 
 */
public class EntitiesFilter implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -2035349550733241119L;

    private long id;
    private List<EntityType> type;
    private String name;
    private Integer certificateAssigned;
    private List<EntityStatus> status;
    private int offset;
    private int limit;

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
     * @return the type
     */
    public List<EntityType> getType() {
        return type;
    }

    /**
     * @param type
     *            the type to set
     */
    public void setType(final List<EntityType> type) {
        this.type = type;
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
     * @return the offset
     */
    public int getOffset() {
        return offset;
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

    /**
     * @param offset
     *            the offset to set
     */
    public void setOffset(final int offset) {
        this.offset = offset;
    }

    /**
     * @return the limit
     */
    public int getLimit() {
        return limit;
    }

    /**
     * @param limit
     *            the limit to set
     */
    public void setLimit(final int limit) {
        this.limit = limit;
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
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + limit;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + offset;
        result = prime * result + ((status == null) ? 0 : status.hashCode());
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

        final EntitiesFilter other = (EntitiesFilter) obj;

        if (certificateAssigned != other.certificateAssigned) {
            return false;
        }
        if (id != other.id) {
            return false;
        }
        if (limit != other.limit) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (offset != other.offset) {
            return false;
        }
        if (status == null) {
            if (other.status != null) {
                return false;
            }
        } else if (!status.equals(other.status)) {
            return false;
        }
        if (type == null) {
            if (other.type != null) {
                return false;
            }
        } else if (!type.equals(other.type)) {
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
        return "EntitiesFilter [id=" + id + ", type=" + type + ", name=" + name + ", certificateAssigned=" + certificateAssigned + ", status=" + status + ", offset=" + offset + ", limit=" + limit
                + "]";
    }
}
