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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto;

import java.io.Serializable;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;

/**
 * Class represents information containing for EndEntity reissue.
 * 
 */
public class EntityReissueDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String name;
    private boolean chain;
    private KeyStoreType format;
    private String password;
    private RevocationReason revocationReason;

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
     * @return the chain
     */
    public boolean isChain() {
        return chain;
    }

    /**
     * @param chain
     *            the chain to set
     */
    public void setChain(final boolean chain) {
        this.chain = chain;
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
    public void setFormat(final KeyStoreType format) {
        this.format = format;
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
     * @return the revocationReason
     */
    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    /**
     * @param revocationReason
     *            the revocationReason to set
     */
    public void setRevocationReason(final RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (chain ? 0 : 1);
        result = prime * result + ((format == null) ? 0 : format.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((password == null) ? 0 : password.hashCode());
        result = prime * result + ((revocationReason == null) ? 0 : revocationReason.hashCode());
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
        final EntityReissueDTO other = (EntityReissueDTO) obj;
        if (chain != other.chain) {
            return false;
        }
        if (format != other.format) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (password == null) {
            if (other.password != null) {
                return false;
            }
        } else if (!password.equals(other.password)) {
            return false;
        }
        if (revocationReason != other.revocationReason) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "EntityReissueDTO [name=" + name + ", chain=" + chain + ", password=" + password + ", format=" + format + ", revocationReason=" + revocationReason + "]";
    }
}