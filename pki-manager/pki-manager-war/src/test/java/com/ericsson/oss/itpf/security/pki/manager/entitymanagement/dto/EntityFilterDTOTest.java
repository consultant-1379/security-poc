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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;

@RunWith(MockitoJUnitRunner.class)
public class EntityFilterDTOTest {

    List<EntityType> type;

    EntityFilterDTO inputEntityFilterDTO;
    EntityFilterDTO expectedEntityFilterDTO;

    @Before
    public void setUp() {

        inputEntityFilterDTO = getEntityFilterDTO();
        inputEntityFilterDTO.hashCode();
        inputEntityFilterDTO.toString();
        expectedEntityFilterDTO = getEntityFilterDTO();

    }

    @Test
    public void testEntityFilterDTO() {

        assertEquals("rest%", inputEntityFilterDTO.getName());
        assertEquals(0, inputEntityFilterDTO.getCertificateAssigned().intValue());
        assertNotNull(inputEntityFilterDTO.getType());

    }

    @Test
    public void testEntityDTOEqual() {

        final boolean equals = expectedEntityFilterDTO.equals(inputEntityFilterDTO);
        assertEquals(true, equals);
        assertEquals(expectedEntityFilterDTO, inputEntityFilterDTO);

    }

    @Test
    public void testEntityDTOEqualilty() {
        final boolean equals = expectedEntityFilterDTO.equals(inputEntityFilterDTO);

        assertEquals(true, equals);

        assertEquals(expectedEntityFilterDTO, inputEntityFilterDTO);

    }

    @Test
    public void testNoName() {

        assertFalse(inputEntityFilterDTO.equals(null));

        assertFalse(inputEntityFilterDTO.equals(new ProfilesDTO()));

        inputEntityFilterDTO.equals(expectedEntityFilterDTO);

        expectedEntityFilterDTO.setCertificateAssigned(1);
        inputEntityFilterDTO.equals(expectedEntityFilterDTO);
        expectedEntityFilterDTO.setCertificateAssigned(0);
    }

    @Test
    public void testNotEqualsDiffType() {

        inputEntityFilterDTO.setName(null);

        inputEntityFilterDTO.equals(expectedEntityFilterDTO);

        inputEntityFilterDTO.setName("res%");
        inputEntityFilterDTO.equals(expectedEntityFilterDTO);

        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        entityTypes.add(EntityType.ENTITY);

        expectedEntityFilterDTO.setType(entityTypes);

        assertFalse(inputEntityFilterDTO.equals(expectedEntityFilterDTO));

        expectedEntityFilterDTO.setType(inputEntityFilterDTO.getType());

        inputEntityFilterDTO.setType(null);
        inputEntityFilterDTO.equals(expectedEntityFilterDTO);

        inputEntityFilterDTO.setType(expectedEntityFilterDTO.getType());

    }

    @Test
    public void testNotEqualsDiffStatus() {

        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        status.add(EntityStatus.INACTIVE);
        inputEntityFilterDTO.setStatus(status);

        assertFalse(inputEntityFilterDTO.equals(expectedEntityFilterDTO));

        inputEntityFilterDTO.setStatus(null);
        assertFalse(inputEntityFilterDTO.equals(expectedEntityFilterDTO));

        inputEntityFilterDTO.setStatus(expectedEntityFilterDTO.getStatus());

    }

    @Test
    public void testNotEqualsNoType() {

        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        status.add(EntityStatus.ACTIVE);

        entityTypes.add(EntityType.ENTITY);

        expectedEntityFilterDTO.setType(entityTypes);

        assertFalse(inputEntityFilterDTO.equals(expectedEntityFilterDTO));

        inputEntityFilterDTO.setType(null);
        assertFalse(inputEntityFilterDTO.equals(expectedEntityFilterDTO));

    }

    private EntityFilterDTO getEntityFilterDTO() {
        final EntityFilterDTO entityFilterDTO = new EntityFilterDTO();

        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        status.add(EntityStatus.ACTIVE);

        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        entityTypes.add(EntityType.CA_ENTITY);

        entityFilterDTO.setCertificateAssigned(0);
        entityFilterDTO.setName("rest%");
        entityFilterDTO.setStatus(status);
        entityFilterDTO.setType(entityTypes);

        return entityFilterDTO;

    }

}
