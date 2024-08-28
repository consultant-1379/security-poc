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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.entity;

import java.io.Serializable;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;

/**
 * Represents Keys generated for the {@link CertificateAuthority}
 * 
 */
@Entity
@Table(name = "key_identifier")
public class KeyIdentifierData implements Serializable {

    private static final long serialVersionUID = -5509726099806005428L;

    @Id
    @SequenceGenerator(name = "SEQ_KEY_IDENTIFIER_ID_GENERATOR", sequenceName = "SEQ_KEY_IDENTIFIER_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_KEY_IDENTIFIER_ID_GENERATOR")
    private long id;

    @Column(name = "key_identifier_id", nullable = false)
    private String keyIdentifier;

    @Column(name = "status_id", nullable = false)
    private Integer status;

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
     * @return the key pair Status
     */
    public KeyPairStatus getStatus() {
        return KeyPairStatus.getStatus(this.status);
    }

    /**
     * @param keyPairStatus
     *            key pair status to be set.
     */
    public void setStatus(final KeyPairStatus keyPairStatus) {

        if (keyPairStatus == null) {
            this.status = null;
        } else {
            this.status = keyPairStatus.getId();
        }
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
     * Returns the has code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        return result;
    }

    /**
     * Indicates whether the invoking object is "equal to" the parameterized object
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
        final KeyIdentifierData other = (KeyIdentifierData) obj;
        if (this.getId() != other.getId()) {
            return false;
        }
        if (this.getKeyIdentifier() == null) {
            if (other.getKeyIdentifier() != null) {
                return false;
            }
        } else if (!this.getKeyIdentifier().equals(other.getKeyIdentifier())) {
            return false;
        }
        if (this.getStatus() == null) {
            if (other.getStatus() != null) {
                return false;
            }
        } else if (!this.getStatus().equals(other.getStatus())) {
            return false;
        }

        return true;
    }

    /**
     * Returns string representation of {@link KeyIdentifierData} object.
     */
    @Override
    public String toString() {
        return "KeyData [id=" + id + "," + "status=" + status + "]";
    }
}
