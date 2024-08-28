/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter;

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

/**
 * <p>
 * This class specifies the filter conditions, offset and limit based on which {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile} has to be fetched
 * </p>
 * 
 * @author tcsgoma
 * 
 */
public class ProfilesFilter implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = 3200030285650979344L;

    private List<ProfileType> type;
    private String name;
    private ProfileStatusFilter status;
    private int offset;
    private int limit;

    /**
     * @return the type
     */
    public List<ProfileType> getType() {
        return type;
    }

    /**
     * @param type
     *            the type to set
     */
    public void setType(final List<ProfileType> type) {
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
     * @return the offset
     */
    public int getOffset() {
        return offset;
    }

    /**
     * @return the status
     */
    public ProfileStatusFilter getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final ProfileStatusFilter status) {
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

        final ProfilesFilter other = (ProfilesFilter) obj;

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
        return "ProfilesFilter [ type =" + type + ", name=" + name + ", status=" + status + ", offset=" + offset + ", limit=" + limit + "]";
    }
}
