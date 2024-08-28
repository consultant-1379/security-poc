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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import static org.junit.Assert.assertNotNull;

import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;

/**
 * This class is to test the ProfileDetailsPersistenceHandler
 * 
 * @author tcsrimrav
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityFilterDynamicQueryBuilderTest {

    @InjectMocks
    EntityFilterDynamicQueryBuilder entityFilterDynamicQueryBuilder;

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityFilterDynamicQueryBuilder.class);

    @Test
    public void testbuildQuery() {
        final EntitiesFilter profilesFilter = getEntitiesFilter();

        StringBuilder dynamicQuery = new StringBuilder();

        Map<String, Object> parameters = entityFilterDynamicQueryBuilder.build(profilesFilter, dynamicQuery);
        assertNotNull(parameters);

    }

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private EntitiesFilter getEntitiesFilter() {

        final EntitiesFilter entitiesFilter = new EntitiesFilter();

        entitiesFilter.setLimit(10);
        entitiesFilter.setOffset(1);
        
        entitiesFilter.setName("R%");

        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        status.add(EntityStatus.ACTIVE);
        entitiesFilter.setStatus(status);

        final List<EntityType> types = new ArrayList<EntityType>();

        types.add(EntityType.CA_ENTITY);
        types.add(EntityType.ENTITY);

        entitiesFilter.setType(types);

        return entitiesFilter;
    }

}
