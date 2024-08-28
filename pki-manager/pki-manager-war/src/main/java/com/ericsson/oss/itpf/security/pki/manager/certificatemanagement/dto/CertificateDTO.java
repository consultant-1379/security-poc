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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto;

import java.io.Serializable;

/**
 * This DTO containing the filter attributes like {@link FilterDTO},offset and limit for Applying the filter to get the certificates.
 */
public class CertificateDTO implements Serializable {

    private static final long serialVersionUID = 1L;
    private FilterDTO filter = null;
    private Integer offset;
    private Integer limit;

    /**
     * @return the filter
     */
    public FilterDTO getFilter() {
        return filter;
    }

    /**
     * @param filter
     *            the filterDTO to set
     */
    public void setFilter(final FilterDTO filter) {
        this.filter = filter;
    }

    /**
     * @return the offset
     */
    public Integer getOffset() {
        return offset;
    }

    /**
     * @param offset
     *            the offset to set
     */
    public void setOffset(final Integer offset) {
        this.offset = offset;
    }

    /**
     * @return the limit
     */
    public Integer getLimit() {
        return limit;
    }

    /**
     * @param limit
     *            the limit to set
     */
    public void setLimit(final Integer limit) {
        this.limit = limit;
    }

    @Override
    public String toString() {
        return "FilterDTO [offset=" + offset + ", limit=" + limit + ", filter=" + filter + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((filter == null) ? 0 : filter.hashCode());
        result = prime * result + (int) (offset ^ (offset >>> 32));
        result = prime * result + (int) (limit ^ (limit >>> 32));
        return result;
    }

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
        final CertificateDTO certificateDTO = (CertificateDTO) obj;
        if (filter == null) {
            if (certificateDTO.filter != null) {
                return false;
            }
        } else if (!filter.equals(certificateDTO.filter)) {
            return false;
        }
        if (offset == null) {
            if (certificateDTO.offset != null) {
                return false;
            }
        } else if (!offset.equals(certificateDTO.offset)) {
            return false;
        }
        if (limit == null) {
            if (certificateDTO.limit != null) {
                return false;
            }
        } else if (!limit.equals(certificateDTO.limit)) {
            return false;
        }
        return true;
    }

}
