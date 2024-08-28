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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.adapter;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;

/**
 * Test class for {@link EntitiesFilterAdapter}
 * 
 * 
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class EntitiesFilterAdapterTest {

    @InjectMocks
    EntitiesFilterAdapter entitiesFilterAdapter;
    @Mock
    EntitiesFilter entitiesFilter;
    @Mock
    EntityFilterDTO entityFilterDTO;
    @Mock
    EntityDTO entityDTO;

    List<EntityType> type;

    @Before
    public void setUp() {

        entityFilterDTO = new EntityFilterDTO();
        entityFilterDTO.setName("TestName");
        entityFilterDTO.setCertificateAssigned(1);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();

        entityFilterDTO.setStatus(status);

        type = new ArrayList<EntityType>();
        type.add(EntityType.CA_ENTITY);

        entityFilterDTO.setType(type);

        entityDTO = new EntityDTO();

        entityDTO.setFilter(entityFilterDTO);
        entityDTO.setId(2);
        entityDTO.setLimit(10);
        entityDTO.setOffset(5);

        entityDTO.setFilter(entityFilterDTO);
    }

    /**
     * Method for testing ToEntitiesFilterForCount
     * 
     * 
     */
    @Test
    public void testToEntitiesFilterForCount() {

        final EntitiesFilter expectedEntitiesFilter = new EntitiesFilter();

        expectedEntitiesFilter.setName("TestName");
        expectedEntitiesFilter.setCertificateAssigned(1);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        expectedEntitiesFilter.setStatus(status);
        expectedEntitiesFilter.setType(type);

        entitiesFilter = entitiesFilterAdapter.toEntitiesFilterForCount(entityFilterDTO);

        assertEquals(expectedEntitiesFilter, entitiesFilter);

    }

    /**
     * Method for testing ToEntitiesFilterForFetch()
     * 
     * 
     */
    @Test
    public void testToEntitiesFilterForFetch() {

        final EntitiesFilter expectedEntitiesFilter = new EntitiesFilter();

        expectedEntitiesFilter.setName("TestName");
        expectedEntitiesFilter.setCertificateAssigned(1);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();

        expectedEntitiesFilter.setStatus(status);

        expectedEntitiesFilter.setType(type);
        expectedEntitiesFilter.setId(2);
        expectedEntitiesFilter.setLimit(10);
        expectedEntitiesFilter.setOffset(5);

        entitiesFilter = entitiesFilterAdapter.toEntitiesFilterForFetch(entityDTO);

        assertEquals(expectedEntitiesFilter, entitiesFilter);
    }

}
