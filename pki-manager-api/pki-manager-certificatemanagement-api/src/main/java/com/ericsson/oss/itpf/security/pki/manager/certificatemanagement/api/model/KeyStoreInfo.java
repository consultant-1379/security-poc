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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model;

import java.io.Serializable;
import java.util.Arrays;

/**
 * This class encapsulates the KeyStore file and the associated password intended to protect the Key contained in the KeyStore file
 *
 */
public class KeyStoreInfo implements Serializable {

    private static final long serialVersionUID = -3358933106325503252L;

    /**
     * Password to protect the Key contained in the KeyStore
     */
    protected char[] password;

    /**
     * Alias name of the Key.
     */
    protected String alias;

    /**
     * The KeyStore file as byte array
     */
    protected byte[] keyStoreFileData;

    /**
     * Returns the password of the KeyStore
     *
     * @return the password
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Sets the password for KeyStore
     *
     * @param password
     *            the password to set
     */
    public void setPassword(final char[] password) {
        this.password = password;
    }

    /**
     * Returns the alias name for the key.
     *
     * @return the alias
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Sets the alias name for the key.
     *
     * @param alias
     *            the alias to set
     */
    public void setAlias(final String alias) {
        this.alias = alias;
    }

    /**
     * @return the keyStoreFileData
     */
    public byte[] getKeyStoreFileData() {
        return keyStoreFileData;
    }

    /**
     * @param keyStoreFileData
     *            the keyStoreFileData to set
     */
    public void setKeyStoreFileData(final byte[] keyStoreFileData) {
        this.keyStoreFileData = keyStoreFileData;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (keyStoreFileData == null ? 0 : Arrays.hashCode(keyStoreFileData));
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
        final KeyStoreInfo other = (KeyStoreInfo) obj;
        if (keyStoreFileData == null) {
            if (other.keyStoreFileData != null) {
                return false;
            }
        } else if (!(Arrays.equals(keyStoreFileData, other.keyStoreFileData))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "KeyStoreInfo [" + (alias == null ? "" : ", alias=" + alias) + "]";
    }
}
