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
import java.util.Arrays;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;

/**
 * This DTO containing the filter attributes like certificateIds,Subject,expiryDateFrom,expiryDateTo,Issuer,type and status for Applying the filter to get the certificates.
 */
public class FilterDTO implements Serializable {

    private static final long serialVersionUID = -650260591675606119L;
    private String subject;
    private Date expiryDateFrom;
    private Date expiryDateTo;
    private String issuer;
    private EntityType[] type;
    private CertificateStatus[] status;

    /**
     * @return the Subject
     */
    public String getSubject() {
        return subject;
    }

    /**
     * @param subject
     *            the SubjectDN to set
     */
    public void setSubject(final String subject) {
        this.subject = subject;
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
     * @return the Issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * @param issuer
     *            the IssuerDN to set
     */
    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    /**
     * @return the type
     */
    public EntityType[] getType() {
        return type;
    }

    /**
     * @param type
     *            the entityTypes to set
     */
    public void setType(final EntityType[] type) {
        this.type = type;
    }

    /**
     * @return the status
     */
    public CertificateStatus[] getStatus() {
        return status;
    }

    /**
     * @param status
     *            the certificateStatusList to set
     */
    public void setStatus(final CertificateStatus[] status) {
        this.status = status;
    }

    /**
     * Returns string representation of {@link CertificateGenerationInfoData} object.
     */
    @Override
    public String toString() {
        return "FilterDTO [ Subject=" + subject + ", expiryDateFrom=" + expiryDateFrom + ", expiryDateTo=" + expiryDateTo + ", Issuer=" + issuer + ", type=" + type + ", status=" + status + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((type == null) ? 0 : Arrays.hashCode(type));
        result = prime * result + ((status == null) ? 0 : Arrays.hashCode(status));
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
        result = prime * result + ((expiryDateFrom == null) ? 0 : expiryDateFrom.hashCode());
        result = prime * result + ((expiryDateTo == null) ? 0 : expiryDateTo.hashCode());
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
        final FilterDTO filter = (FilterDTO) obj;
        if (type == null) {
            if (filter.type != null) {
                return false;
            }
        } else if (! Arrays.equals(type, filter.type)) {
            return false;
        }
        if (status == null) {
            if (filter.status != null) {
                return false;
            }
        } else if (! Arrays.equals(status, filter.status)) {
            return false;
        }
        if (subject == null) {
            if (filter.subject != null) {
                return false;
            }
        } else if (!subject.equals(filter.subject)) {
            return false;
        }
        if (expiryDateFrom == null) {
            if (filter.expiryDateFrom != null) {
                return false;
            }
        } else if (!expiryDateFrom.equals(filter.expiryDateFrom)) {
            return false;
        }

        if (expiryDateTo == null) {
            if (filter.expiryDateTo != null) {
                return false;
            }
        } else if (!expiryDateTo.equals(filter.expiryDateTo)) {
            return false;
        }
        if (issuer == null) {
            if (filter.issuer != null) {
                return false;
            }
        } else if (!issuer.equals(filter.issuer)) {
            return false;
        }
        return true;
    }

}
