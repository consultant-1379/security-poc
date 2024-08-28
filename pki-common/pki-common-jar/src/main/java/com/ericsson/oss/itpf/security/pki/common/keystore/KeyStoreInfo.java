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
package com.ericsson.oss.itpf.security.pki.common.keystore;

import java.io.Serializable;

/**
 * This class contains filePath, keyStoreType, aliasName and password for loading KeyStore.
 * 
 * @author xjagcho
 * 
 */
public class KeyStoreInfo implements Serializable {
    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((aliasName == null) ? 0 : aliasName.hashCode());
        result = prime * result + ((filePath == null) ? 0 : filePath.hashCode());
        result = prime * result + ((keyStoreType == null) ? 0 : keyStoreType.hashCode());
        result = prime * result + ((password == null) ? 0 : password.hashCode());
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

        final KeyStoreInfo other = (KeyStoreInfo) obj;
        if (aliasName == null) {
            if (other.aliasName != null) {
                return false;
            }
        } else if (!aliasName.equals(other.aliasName)) {
            return false;
        }

        if (filePath == null) {
            if (other.filePath != null) {
                return false;
            }
        } else if (!filePath.equals(other.filePath)) {
            return false;
        }

        if (keyStoreType != other.keyStoreType) {
            return false;
        }

        if (password == null) {
            if (other.password != null) {
                return false;
            }
        } else if (!password.equals(other.password)) {
            return false;
        }

        return true;
    }

    /**
     *
     */
    private static final long serialVersionUID = 5455969413105123782L;

    private String filePath;

    private KeyStoreType keyStoreType;

    private String password;

    private String aliasName;

    public KeyStoreInfo() {
        super();
    }

    /**
     * @param filePath
     *            Path in which file is present.
     * @param keyStoreType
     *            Type of keyStore which needs to be used.
     * @param password
     *            password of the file
     * @param aliasName
     *            name of the alias
     */
    public KeyStoreInfo(final String filePath, final KeyStoreType keyStoreType, final String password, final String aliasName) {
        super();
        this.filePath = filePath;
        this.keyStoreType = keyStoreType;
        this.password = password;
        this.aliasName = aliasName;
    }

    /**
     * @return the filePath
     */
    public String getFilePath() {
        return filePath;
    }

    /**
     * @param filePath
     *            the filePath to set
     */
    public void setFilePath(final String filePath) {
        this.filePath = filePath;
    }

    /**
     * @return the keyStoreType
     */
    public KeyStoreType getKeyStoreType() {
        return keyStoreType;
    }

    /**
     * @param keyStoreType
     *            the keyStoreType to set
     */
    public void setKeyStoreType(final KeyStoreType keyStoreType) {
        this.keyStoreType = keyStoreType;
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
     * @return the aliasName
     */
    public String getAliasName() {
        return aliasName;
    }

    /**
     * @param aliasName
     *            the aliasName to set
     */
    public void setAliasName(final String aliasName) {
        this.aliasName = aliasName;
    }

}
