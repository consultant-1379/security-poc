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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration;

import static org.mockito.Mockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.EntityCategoryValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityCategorySetUpData;

@RunWith(MockitoJUnitRunner.class)
public class EntityCategoryValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityCategoryValidator.class);

    @InjectMocks
    EntityCategoryValidator entityCategoryValidator;

    @Mock
    PersistenceManager persistenceManager;

    @Test
    public void testEntityCategory_ValidParams() {
        final EntityCategorySetUpData entityCategorySetUpData = new EntityCategorySetUpData();
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategorySetUpData.getEntityCategory().getName(), EntityCategorySetUpData.NAME_PATH)).thenReturn(
                entityCategorySetUpData.getEntityCategoryData());
        entityCategoryValidator.validate(entityCategorySetUpData.getEntityCategory());
    }

    @Test(expected = EntityCategoryNotFoundException.class)
    public void testEntityCategory_InvalidCategory() {
        entityCategoryValidator.validate(null);
    }

    @Test(expected = InvalidEntityCategoryException.class)
    public void testEntityCategory_InValidParams() {
        final EntityCategorySetUpData entityCategorySetUpData = new EntityCategorySetUpData();
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategorySetUpData.getEntityCategory().getName(), EntityCategorySetUpData.NAME_PATH)).thenReturn(null);
        entityCategoryValidator.validate(entityCategorySetUpData.getEntityCategory());
    }
}
