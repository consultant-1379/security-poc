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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import java.io.Serializable;
import java.util.Arrays;

import javax.persistence.*;

/**
 * 
 * Represents the subject jpa entity to manage additional subject details of an entity like the hash of subject DN etc
 *
 */
@Entity
@Table(name = "subject_identification_details")
public class SubjectIdentificationData implements Serializable {

    private static final long serialVersionUID = 6545496725018019950L;

    @Id
    @SequenceGenerator(name = "SEQ_SUBJECT_IDENTIFICATION_DETAILS_ID_GENERATOR", sequenceName = "SEQ_SUBJECT_IDENTIFICATION_DETAILS_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_SUBJECT_IDENTIFICATION_DETAILS_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "entity_id", nullable = false)
    private long entityId;

    @Column(name = "subject_dn_hash", nullable = false)
    private byte[] subjectDNHash;

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
     * @return the entityId
     */
    public long getEntityId() {
        return entityId;
    }

    /**
     * @param entityId
     *            the entityId to set
     */
    public void setEntityId(final long entityId) {
        this.entityId = entityId;
    }

    /**
     * @return the subjectDNHash
     */
    public byte[] getSubjectDNHash() {
        return subjectDNHash;
    }

    /**
     * @param subjectDNHash
     *            the subjectDNHash to set
     */
    public void setSubjectDNHash(final byte[] subjectDNHash) {
        this.subjectDNHash = subjectDNHash;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + (int) (entityId ^ (entityId >>> 32));
        result = prime * result + Arrays.hashCode(subjectDNHash);
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

        final SubjectIdentificationData other = (SubjectIdentificationData) obj;
        if (!Arrays.equals(subjectDNHash, other.subjectDNHash)) {
            return false;
        }

        if (id != other.id) {
            return false;
        }

        if (entityId != other.entityId) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return "SubjectIdentificationData [id=" + id + ", entityId=" + entityId + ", subjectDNHash=" + Arrays.toString(subjectDNHash) + "]";
    }

}
