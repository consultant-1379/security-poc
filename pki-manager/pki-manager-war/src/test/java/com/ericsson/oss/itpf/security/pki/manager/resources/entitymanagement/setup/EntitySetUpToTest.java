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
package com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.setup;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.EntityProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.setup.AlgorithmSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.setup.EntityCategorySetUpToTest;

/**
 * Class for Test Data creation for {@link Entity}
 * 
 * @version 1.2.4
 */
public class EntitySetUpToTest {

    private Entity entity;

    /**
     * Method to provide dummy data for tests.
     */
    public EntitySetUpToTest() {
        fillEntity();
    }

    /**
     * Method that returns Entity object for tests.
     */
    public Entity getEntity() {
        return entity;
    }

    private void fillEntity() {
        entity = new Entity();

        entity.setCategory(new EntityCategorySetUpToTest().getEntityCategories().get(0));
        entity.setEntityProfile(new EntityProfileSetUpToTest().getEntityProfile());
        entity.setKeyGenerationAlgorithm(new AlgorithmSetUpToTest().getKeyGenerationAlgorithmList().get(0));
        entity.setEntityInfo(createEntityInfo());
        entity.setPublishCertificatetoTDPS(true);
        entity.setType(EntityType.ENTITY);
    }

    private EntityInfo createEntityInfo() {
        final EntityInfo entityInfo = new EntityInfo();

        entityInfo.setId(1);
        entityInfo.setName("rest_end_entity");
        entityInfo.setOTP("230RPsdfff9");
        entityInfo.setOTPCount(2);
        entityInfo.setStatus(EntityStatus.ACTIVE);
        entityInfo.setSubject(new SubjectSetUpToTest().getSubject());
        entityInfo.setSubjectAltName(new SubjectAltNameSetUpToTest().getSubjectAltName());

        return entityInfo;
    }
}
