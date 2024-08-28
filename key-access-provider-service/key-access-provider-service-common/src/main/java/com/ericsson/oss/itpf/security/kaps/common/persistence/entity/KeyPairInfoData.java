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
import java.util.Date;

import javax.persistence.*;

/**
 * The persistent class for the keypairinfo database table.
 *
 */
@Entity
@Table(name = "keypair_info")
public class KeyPairInfoData implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @SequenceGenerator(name = "SEQ_KEYPAIR_INFO_ID_GENERATOR", sequenceName = "SEQ_KEYPAIR_INFO_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_KEYPAIR_INFO_ID_GENERATOR")
    private long id;

    private String keyIdentifier;

    @Column(nullable = false)
    private String algorithm;

    @Column(nullable = false)
    private Integer keysize;

    @Column(nullable = false)
    @Temporal(TemporalType.DATE)
    private Date createdtime;

    @Column(nullable = false)
    @Temporal(TemporalType.DATE)
    private Date updatedtime;

    @Column(nullable = false)
    private byte[] publickey;

    @OneToOne
    @JoinColumn(name = "encrypted_privatekey_info_id")
    private EncryptedPrivateKeyInfoData encryptedprivatekeyinfo;

    @Column(name = "status_id", nullable = false)
    private Integer keyPairStatus;

    /**
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * @param algorithm
     *            the algorithm to set
     */
    public void setAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * @return the keysize
     */
    public Integer getKeysize() {
        return keysize;
    }

    /**
     * @param keysize
     *            the keysize to set
     */
    public void setKeysize(final Integer keysize) {
        this.keysize = keysize;
    }

    /**
     * @return the createdtime
     */
    public Date getCreatedtime() {
        return createdtime;
    }

    /**
     * @param createdtime
     *            the createdtime to set
     */
    public void setCreatedtime(final Date createdtime) {
        this.createdtime = createdtime;
    }

    /**
     * @return the updatedtime
     */
    public Date getUpdatedtime() {
        return updatedtime;
    }

    /**
     * @param updatedtime
     *            the updatedtime to set
     */
    public void setUpdatedtime(final Date updatedtime) {
        this.updatedtime = updatedtime;
    }

    /**
     * @return the publickey
     */
    public byte[] getPublickey() {
        return publickey;
    }

    /**
     * @param publickey
     *            the publickey to set
     */
    public void setPublickey(final byte[] publickey) {
        this.publickey = publickey;
    }

    /**
     * @return the encryptedprivatekeyinfo
     */
    public EncryptedPrivateKeyInfoData getEncryptedprivatekeyinfo() {
        return encryptedprivatekeyinfo;
    }

    /**
     * @param encryptedprivatekeyinfo
     *            the encryptedprivatekeyinfo to set
     */
    public void setEncryptedprivatekeyinfo(final EncryptedPrivateKeyInfoData encryptedprivatekeyinfo) {
        this.encryptedprivatekeyinfo = encryptedprivatekeyinfo;
    }

    /**
     * @return the keyPairStatus
     */
    public Integer getKeyPairStatus() {
        return keyPairStatus;
    }

    /**
     * @param keyPairStatus
     *            the keyPairStatus to set
     */
    public void setKeyPairStatus(final Integer keyPairStatus) {
        this.keyPairStatus = keyPairStatus;
    }

    /**
     * @return the keyIdentifier
     */
    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * @param keyIdentifier
     *            the keyIdentifier to set
     */
    public void setKeyIdentifier(final String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
        result = prime * result + ((createdtime == null) ? 0 : createdtime.hashCode());
        result = prime * result + ((encryptedprivatekeyinfo == null) ? 0 : encryptedprivatekeyinfo.hashCode());
        result = prime * result + ((keyIdentifier == null) ? 0 : keyIdentifier.hashCode());
        result = prime * result + ((keyPairStatus == null) ? 0 : keyPairStatus.hashCode());
        result = prime * result + ((keysize == null) ? 0 : keysize.hashCode());
        result = prime * result + Arrays.hashCode(publickey);
        result = prime * result + ((updatedtime == null) ? 0 : updatedtime.hashCode());
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
        final KeyPairInfoData other = (KeyPairInfoData) obj;
        if (id != other.id) {
            return false;
        }
        if (algorithm == null) {
            if (other.algorithm != null) {
                return false;
            }
        } else if (!algorithm.equals(other.algorithm)) {
            return false;
        }
        if (createdtime == null) {
            if (other.createdtime != null) {
                return false;
            }
        } else if (!createdtime.equals(other.createdtime)) {
            return false;
        }
        if (encryptedprivatekeyinfo == null) {
            if (other.encryptedprivatekeyinfo != null) {
                return false;
            }
        } else if (!encryptedprivatekeyinfo.equals(other.encryptedprivatekeyinfo)) {
            return false;
        }
        if (keyIdentifier != other.keyIdentifier) {
            return false;
        }
        if (keyPairStatus == null) {
            if (other.keyPairStatus != null) {
                return false;
            }
        } else if (!keyPairStatus.equals(other.keyPairStatus)) {
            return false;
        }
        if (keysize == null) {
            if (other.keysize != null) {
                return false;
            }
        } else if (!keysize.equals(other.keysize)) {
            return false;
        }
        if (!Arrays.equals(publickey, other.publickey)) {
            return false;
        }
        if (updatedtime == null) {
            if (other.updatedtime != null) {
                return false;
            }
        } else if (!updatedtime.equals(other.updatedtime)) {
            return false;
        }
        return true;
    }

    /**
     * Returns string representation of {@link KeyPairInfoData} object.
     */
    @Override
    public String toString() {
        return "KeyPairInfoData [id=" + id + ", algorithm=" + algorithm + ", keysize=" + keysize + ", createdtime=" + createdtime + ", updatedtime=" + updatedtime + ",  keyPairStatus="
                + keyPairStatus + "]";
    }

}