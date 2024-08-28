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

import javax.persistence.*;

/**
 * The persistent class for the symmetric key table.
 * 
 */
@Entity
@Table(name = "symmetric_key")
public class SymmetricKeyData implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @SequenceGenerator(name = "SEQ_SYMMETRIC_KEY_ID_GENERATOR", sequenceName = "SEQ_SYMMETRIC_KEY_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_SYMMETRIC_KEY_ID_GENERATOR")
    private long id;

    @Column(name = "symmetrickey", nullable = false)
    private byte[] symmetricKey;

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
     * @return the symmetricKey
     */
    public byte[] getSymmetricKey() {
        return symmetricKey;
    }

    /**
     * @param symmetricKey
     *            the symmetricKey to set
     */
    public void setSymmetricKey(final byte[] symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

}