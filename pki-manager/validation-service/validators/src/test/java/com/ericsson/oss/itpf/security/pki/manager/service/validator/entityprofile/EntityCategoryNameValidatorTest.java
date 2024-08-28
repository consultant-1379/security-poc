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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.EntityCategoryValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.EntityCategoryNameValidator;

@RunWith(MockitoJUnitRunner.class)
public class EntityCategoryNameValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityCategoryNameValidator.class);

    @Spy
    final Logger logger1 = LoggerFactory.getLogger(EntityCategoryValidator.class);

    @InjectMocks
    EntityCategoryNameValidator entityCategoryNameValidator;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityCategoryValidator entityCategoryValidator;

    private EntityProfile entityProfile = null;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        final EntityProfileSetUpData entityProfileSetUpData = new EntityProfileSetUpData();
        entityProfile = entityProfileSetUpData.getEntityProfile();
    }

    /**
     * Method to test negative scenario.
     */
    @Test
    public void testCreateProfile_InValidEntityCategory() {
        entityCategoryNameValidator.validate(entityProfile);
    }

}
