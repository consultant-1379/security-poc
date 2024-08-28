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

package com.ericsson.oss.itpf.security.kaps.common.persistence.entity;

import java.io.Serializable;
import java.util.Arrays;

import javax.persistence.*;

/**
 * The persistent class for the encrypted privatekeyinfo database table.
 */
@Entity
@Table(name = "encrypted_privatekey_info")
public class EncryptedPrivateKeyInfoData implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @SequenceGenerator(name = "SEQ_ENCRYPTED_PRIVATEKEY_INFO_ID_GENERATOR", sequenceName = "SEQ_ENCRYPTED_PRIVATEKEY_INFO_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_ENCRYPTED_PRIVATEKEY_INFO_ID_GENERATOR")
    private long id;

    private byte[] privatekey;

    @Column(name = "privatekey_hash")
    private byte[] hashOfPrivateKey;

    /**
     * @return the id
     */
    public long getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * @return the privatekey
     */
    public byte[] getPrivatekey() {
        return privatekey;
    }

    /**
     * @param privatekey
     *            the privatekey to set
     */
    public void setPrivatekey(final byte[] privatekey) {
        this.privatekey = privatekey;
    }

    /**
     * @return the hashOfPrivateKey
     */
    public byte[] getHashOfPrivateKey() {
        return hashOfPrivateKey;
    }

    /**
     * @param hashOfPrivateKey
     *            the hashOfPrivateKey to set
     */
    public void setHashOfPrivateKey(final byte[] hashOfPrivateKey) {
        this.hashOfPrivateKey = hashOfPrivateKey;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + Arrays.hashCode(privatekey);
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

        final EncryptedPrivateKeyInfoData other = (EncryptedPrivateKeyInfoData) obj;

        if (id != other.id) {
            return false;
        }
        if (!Arrays.equals(privatekey, other.privatekey)) {
            return false;
        }
        if (!Arrays.equals(hashOfPrivateKey, other.hashOfPrivateKey)) {
            return false;
        }
        return true;
    }

    /**
     * Returns string representation of {@link EncryptedPrivateKeyInfoData} object.
     */
    @Override
    public String toString() {
        return "EncryptedPrivateKeyInfoData [id=" + id + "]";
    }

}
