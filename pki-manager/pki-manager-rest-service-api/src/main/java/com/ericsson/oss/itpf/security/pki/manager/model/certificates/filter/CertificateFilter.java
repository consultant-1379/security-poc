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
package com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

public class CertificateFilter implements Serializable {

    private static final long serialVersionUID = 6176821339933063471L;

    private Long[] certificateIdList;
    private Date expiryDateFrom;
    private Date expiryDateTo;
    private String subjectDN;
    private String issuerDN;
    private EntityType[] entityTypes;
    private CertificateStatus[] certificateStatusList;
    private Integer offset;
    private Integer limit;

    /**
     * @return the certificateIdList
     */
    public Long[] getCertificateIdList() {
        return certificateIdList;
    }

    /**
     * @param certificateIdList
     *            the certificateIdList to set
     */
    public void setCertificateIdList(final Long[] certificateIdList) {
        this.certificateIdList = certificateIdList;
    }

    /**
     * @return the expiryDateFrom
     */
    public Date getExpiryDateFrom() {
        return expiryDateFrom;
    }

    /**
     * @param expiryDateFrom
     *            the expiryDateFrom to set
     */
    public void setExpiryDateFrom(final Date expiryDateFrom) {
        this.expiryDateFrom = expiryDateFrom;
    }

    /**
     * @return the expiryDateTo
     */
    public Date getExpiryDateTo() {
        return expiryDateTo;
    }

    /**
     * @param expiryDateTo
     *            the expiryDateTo to set
     */
    public void setExpiryDateTo(final Date expiryDateTo) {
        this.expiryDateTo = expiryDateTo;
    }

    /**
     * @return the subjectDN
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * @param subjectDN
     *            the subjectDN to set
     */
    public void setSubjectDN(final String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * @return the issuerDN
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * @param issuerDN
     *            the issuerDN to set
     */
    public void setIssuerDN(final String issuerDN) {
        this.issuerDN = issuerDN;
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

    /**
     * @return the entityTypes
     */
    public EntityType[] getEntityTypes() {
        return entityTypes;
    }

    /**
     * @param entityTypes
     *            the entityTypes to set
     */
    public void setEntityTypes(final EntityType[] entityTypes) {
        this.entityTypes = entityTypes;
    }

    /**
     * @return the certificateStatusList
     */
    public CertificateStatus[] getCertificateStatusList() {
        return certificateStatusList;
    }

    /**
     * @param certificateStatusList
     *            the certificateStatusList to set
     */
    public void setCertificateStatusList(final CertificateStatus[] certificateStatusList) {
        this.certificateStatusList = certificateStatusList;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entityTypes == null) ? 0 : Arrays.hashCode(entityTypes));
        result = prime * result + ((certificateStatusList == null) ? 0 : Arrays.hashCode(certificateStatusList));
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + (int) (Arrays.hashCode(certificateIdList));
        result = prime * result + ((expiryDateFrom == null) ? 0 : expiryDateFrom.hashCode());
        result = prime * result + ((expiryDateTo == null) ? 0 : expiryDateTo.hashCode());
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
        final CertificateFilter certificateFilter = (CertificateFilter) obj;
        if (entityTypes == null) {
            if (certificateFilter.entityTypes != null) {
                return false;
            }
        } else if (!(entityTypes==certificateFilter.entityTypes)) {
            return false;
        }
        if (certificateStatusList == null) {
            if (certificateFilter.certificateStatusList != null) {
                return false;
            }
        } else if (!(certificateStatusList==certificateFilter.certificateStatusList)) {
            return false;
        }
        if (certificateIdList == null) {
            if (certificateFilter.certificateIdList != null) {
                return false;
            }
        } else if (!(certificateIdList==certificateFilter.certificateIdList)) {
            return false;
        }
        if (subjectDN == null) {
            if (certificateFilter.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(certificateFilter.subjectDN)) {
            return false;
        }
        if (expiryDateFrom == null) {
            if (certificateFilter.expiryDateFrom != null) {
                return false;
            }
        } else if (!expiryDateFrom.equals(certificateFilter.expiryDateFrom)) {
            return false;
        }

        if (expiryDateTo == null) {
            if (certificateFilter.expiryDateTo != null) {
                return false;
            }
        } else if (!expiryDateTo.equals(certificateFilter.expiryDateTo)) {
            return false;
        }
        if (issuerDN == null) {
            if (certificateFilter.issuerDN != null) {
                return false;
            }
        } else if (!issuerDN.equals(certificateFilter.issuerDN)) {
            return false;
        }
        if (offset == null) {
            if (certificateFilter.offset != null) {
                return false;
            }
        } else if (!offset.equals(certificateFilter.offset)) {
            return false;
        }
        if (limit == null) {
            if (certificateFilter.limit != null) {
                return false;
            }
        } else if (!limit.equals(certificateFilter.limit)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "CertificateFilter [certificateIdList=" + Arrays.toString(certificateIdList) + ", expiryDateFrom=" + expiryDateFrom + ", expiryDateTo=" + expiryDateTo + ", subjectDN=" + subjectDN
                + ", issuerDN=" + issuerDN + ", entityTypes=" + Arrays.toString(entityTypes) + ", certificateStatusList=" + Arrays.toString(certificateStatusList) + ", offset=" + offset + ", limit="
                + limit + "]";
    }

}
