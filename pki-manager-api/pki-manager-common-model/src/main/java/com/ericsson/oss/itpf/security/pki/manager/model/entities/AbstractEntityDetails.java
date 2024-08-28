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
package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

/**
 * This class contains the parameters which holds the caentity and entity combined data. This class is accessed during UNION operation of caentity and
 * entity tables. This class is extended by CAEntityDetails and EntityDetails.
 *
 * @author tcssote
 */
public abstract class AbstractEntityDetails {
    boolean publishCertificatetoTDPS;
    EntityProfile entityProfile;
    Algorithm keyGenerationAlgorithm;
    EntityType type;

    public AbstractEntityDetails(final boolean publishCertificatetoTDPS, final EntityProfile entityProfile, final Algorithm keyGenerationAlgorithm,
                                 final EntityType type) {

        this.publishCertificatetoTDPS = publishCertificatetoTDPS;
        this.entityProfile = entityProfile;
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
        this.type = type;
    }

    /**
     * @return the publishCertificatetoTDPS
     */
    public boolean isPublishCertificatetoTDPS() {

        return publishCertificatetoTDPS;
    }

    /**
     * @param publishCertificatetoTDPS
     *            the publishCertificatetoTDPS to set
     */
    public void setPublishCertificatetoTDPS(final boolean publishCertificatetoTDPS) {
        this.publishCertificatetoTDPS = publishCertificatetoTDPS;
    }

    /**
     * @return the type
     */
    public EntityType getType() {
        return type;
    }

    /**
     * @param type
     *            the type to set
     */
    public void setType(final EntityType type) {
        this.type = type;
    }

    /**
     * @return the keyGenerationAlgorithm
     */
    public Algorithm getKeyGenerationAlgorithm() {
        return keyGenerationAlgorithm;
    }

    /**
     * @param keyGenerationAlgorithm
     *            the keyGenerationAlgorithm to set
     */
    public void setKeyGenerationAlgorithm(final Algorithm keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
    }

    /**
     * @return the entityProfile
     */
    public EntityProfile getEntityProfile() {
        return entityProfile;
    }

    /**
     * @param entityProfile
     *            the entityProfile to set
     */
    public void setEntityProfile(final EntityProfile entityProfile) {
        this.entityProfile = entityProfile;
    }
}
