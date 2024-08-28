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

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;

/**
 * DownloadDTO contains the attribute certificateIds to get the certificates and type to return a certificate with the given type/extension.
 */
public class DownloadDTO implements Serializable {

    private static final long serialVersionUID = 1L;
    private Long[] certificateIds;
    private String password;
    private KeyStoreType format;

    /**
     * @return the certificateIds
     */
    public Long[] getCertificateIds() {
        return certificateIds;
    }

    /**
     * @param ids
     *            the certificateIds to set
     */
    public void setCertificateIds(final Long[] ids) {
        this.certificateIds = ids;
    }

    /**
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * @param password
     *            the password to set
     */
    public void setPassword(final String password) {
        this.password = password;
    }

    /**
     * @return the format
     */
    public KeyStoreType getFormat() {
        return format;
    }

    /**
     * @param format
     *            the format to set
     */
    public void setFormat(final KeyStoreType extension) {
        this.format = extension;
    }

    /**
     * Returns string representation of {@link DownloadDTO} object.
     */
    @Override
    public String toString() {
        return "DownloadDTO [certificateIds=" + Arrays.toString(certificateIds) + ", format=" + format + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((format == null) ? 0 : format.hashCode());
        result = prime * result + Arrays.hashCode(certificateIds);
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
        final DownloadDTO other = (DownloadDTO) obj;
        if (format != other.format) {
            return false;
        }

        return Arrays.equals(certificateIds, other.certificateIds);
    }

}
