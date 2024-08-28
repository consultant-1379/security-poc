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

/**
 * <p>
 * This class specifies filter conditions, offset and limit based on which entities has to be filtered and specifies the ID of the entity that has to be placed in the first row.
 * </p>
 * 
 * @author tcspred
 */
public class EntityDTO implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 4310363878278847232L;

    protected long id;
    protected EntityFilterDTO filter;
    protected int offset;
    protected int limit;

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
     * @return the filterDTO
     */
    public EntityFilterDTO getFilter() {
        return filter;
    }

    /**
     * @param filterDTO
     *            the filterDTO to set
     */
    public void setFilter(final EntityFilterDTO filter) {
        this.filter = filter;
    }

    /**
     * @return the offset
     */
    public int getOffset() {
        return offset;
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

        result = prime * result + ((filter == null) ? 0 : filter.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + limit;
        result = prime * result + offset;

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

        final EntityDTO other = (EntityDTO) obj;

        if (filter == null) {
            if (other.filter != null) {
                return false;
            }
        } else if (!filter.equals(other.filter)) {
            return false;
        }
        if (id != other.id) {
            return false;
        }
        if (limit != other.limit) {
            return false;
        }
        if (offset != other.offset) {
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
        return "EntityDTO [id=" + id + ", filterDTO=" + filter + ", offset=" + offset + ", limit=" + limit + "]";
    }
}
