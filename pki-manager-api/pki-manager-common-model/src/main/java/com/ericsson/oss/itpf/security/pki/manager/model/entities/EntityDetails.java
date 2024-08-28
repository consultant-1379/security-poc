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
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

/**
 * This class contains the data specific to Entity. The parameters which are common to both the caentity and entity are extended from EntityDetails
 * abstract class.
 *
 * @author tcssote
 */
public class EntityDetails extends AbstractEntityDetails {
    EntityInfo entityInfo;

    public EntityDetails(final boolean publishCertificatetoTDPS, final EntityProfile entityProfile, final Algorithm keyGenerationAlgorithm,
                            final EntityType type, final EntityInfo entityInfo) {
        super(publishCertificatetoTDPS, entityProfile, keyGenerationAlgorithm, type);
        this.entityInfo = entityInfo;
    }

    /**
     * @return the entityInfo
     */
    public EntityInfo getEntityInfo() {
        return entityInfo;
    }

    /**
     * @param entityInfo
     *            the entityInfo to set
     */
    public void setEntityInfo(final EntityInfo entityInfo) {
        this.entityInfo = entityInfo;
    }
}
