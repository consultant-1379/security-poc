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
package com.ericsson.oss.itpf.security.kaps.model.holder;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Holder class for representing the certificate extension
 *
 * @author xramcho
 *
 */
public class CertificateExtensionHolder implements Serializable {

    private static final long serialVersionUID = 8890921788278427773L;

    private String extnId;

    private boolean critical;

    private byte[] value;

    public CertificateExtensionHolder(final String extnId, final boolean critical, final byte[] value) {
        this.extnId = extnId;
        this.critical = critical;
        this.value = value;
    }

    /**
     * @return the extnId
     */
    public String getExtnId() {
        return extnId;
    }

    /**
     * @param extnId
     *            the extnId to set
     */
    public void setExtnId(final String extnId) {
        this.extnId = extnId;
    }

    /**
     * @return the critical
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * @param critical
     *            the critical to set
     */
    public void setCritical(final boolean critical) {
        this.critical = critical;
    }

    /**
     * @return the value
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * @param value
     *            the value to set
     */
    public void setValue(final byte[] value) {
        this.value = value;
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
        result = prime * result + (extnId == null ? 0 : extnId.hashCode());
        result = prime * result + (critical ? 1231 : 1237);
        result = prime * result + (value == null ? 0 : Arrays.hashCode(value));
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
        final CertificateExtensionHolder other = (CertificateExtensionHolder) obj;
        if (extnId == null) {
            if (other.extnId != null) {
                return false;
            }
        } else if (!extnId.equals(other.extnId)) {
            return false;
        }
        if (critical != other.critical) {
            return false;
        }
        if (value == null) {
            if (other.value != null) {
                return false;
            }
        } else if (!(Arrays.equals(value, other.value))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "ExtensionHolder [extnId=" + extnId + ", critical=" + critical + "]";
    }

}
