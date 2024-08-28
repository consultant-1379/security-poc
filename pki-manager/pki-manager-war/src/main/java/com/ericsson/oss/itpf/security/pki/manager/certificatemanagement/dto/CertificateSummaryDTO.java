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

import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;

/**
 * This DTO containing the filter attributes like entityName and entityType for Applying the filter to get the certificates summary issued by the CA entity.
 */

public class CertificateSummaryDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String name;
    private EntityType type;

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
     * @return the entityType
     */
    public EntityType getType() {
        return type;
    }

    /**
     * @param entityType
     *            the entityType to set
     */
    public void setType(final EntityType type) {
        this.type = type;
    }

    /**
     * Returns string representation of {@link CertificateGenerationInfoData} object.
     */
    @Override
    public String toString() {
        return "CertificateSummaryDTO [name=" + name + ", type=" + type + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
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
        final CertificateSummaryDTO certificateSummaryDTO = (CertificateSummaryDTO) obj;
        if (type == null) {
            if (certificateSummaryDTO.type != null) {
                return false;
            }
        } else if (!type.equals(certificateSummaryDTO.type)) {
            return false;
        }
        if (name == null) {
            if (certificateSummaryDTO.name != null) {
                return false;
            }
        } else if (!name.equals(certificateSummaryDTO.name)) {
            return false;
        }
        return true;
    }

}
