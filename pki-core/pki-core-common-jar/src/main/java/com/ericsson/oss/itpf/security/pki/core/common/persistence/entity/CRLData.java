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
import java.util.Arrays;

import javax.persistence.*;

/**
 * @author tcsnapa
 *
 */
@Entity
@Table(name = "CRL")
public class CRLData implements Serializable {

    private static final long serialVersionUID = -2187652562878709281L;
    @Id
    @SequenceGenerator(name = "SEQ_CRL_ID_GENERATOR", sequenceName = "SEQ_CRL_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CRL_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "crl", nullable = false)
    private byte[] crl;

    /**
     * @return the id
     */
    public long getId() {
        return id;
    }

    /**
     * @param id the id to set
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * @return the crl
     */
    public byte[] getCrl() {
        return crl;
    }

    /**
     * @param crl the crl to set
     */
    public void setCrl(final byte[] crl) {
        this.crl = crl;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + Arrays.hashCode(crl);
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
        
        final CRLData other = (CRLData) obj;
        if (!Arrays.equals(crl, other.crl)) {
            return false;
        }
        
        if (id != other.id) {
            return false;
        }
        
        return true;
    }

    @Override
    public String toString() {
        return "CRLData [id=" + id + ", crl=" + Arrays.toString(crl) + "]";
    }
}