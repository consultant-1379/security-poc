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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.validators;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.EntityDTO;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.EntityFilterDTO;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class DTOValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(DTOValidator.class);

    @InjectMocks
    DTOValidator dtoValidator;

    @Mock
    EntityFilterDTO entityFilterDTO;
    List<EntityType> type;
    @Mock
    EntityDTO entityDTO;

    @Before
    public void setUp() {

        dtoValidator = new DTOValidator();
        entityFilterDTO = new EntityFilterDTO();
        entityFilterDTO.setName("TestName");
        entityFilterDTO.setCertificateAssigned(1);

        type = new ArrayList<EntityType>();
        type.add(EntityType.CA_ENTITY);

        entityFilterDTO.setType(type);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();

        status.add(EntityStatus.ACTIVE);
        status.add(EntityStatus.INACTIVE);

        entityFilterDTO.setStatus(status);

        entityDTO = new EntityDTO();

        entityDTO.setFilter(entityFilterDTO);
        entityDTO.setId(2);
        entityDTO.setLimit(10);
        entityDTO.setOffset(5);

        entityDTO.setFilter(entityFilterDTO);
    }

    @Test
    public void testvalidateEntityFilterDTO() {

        final boolean isvalid = dtoValidator.validateEntityFilterDTO(entityFilterDTO);
        assertEquals(true, isvalid);
    }

    @Test
    public void testvalidateEntityDTO() {

        final boolean isvalid = dtoValidator.validateEntityDTO(entityDTO);
        assertEquals(true, isvalid);
    }

    @Test
    public void testvalidateEntityFilterDTOInValidNullType() {
        entityFilterDTO.setType(null);

        final boolean isvalid = dtoValidator.validateEntityFilterDTO(entityFilterDTO);
        assertEquals(false, isvalid);
    }

    @Test
    public void testvalidateEntityFilterDTOInValidNullName() {

        entityFilterDTO.setType(null);

        final boolean isvalid = dtoValidator.validateEntityFilterDTO(entityFilterDTO);
        assertEquals(false, isvalid);
    }

    @Test
    public void testvalidateEntityFilterDTOInValidNullStatus() {

        entityFilterDTO.setStatus(null);

        final boolean isvalid = dtoValidator.validateEntityFilterDTO(entityFilterDTO);
        assertEquals(false, isvalid);
    }

    @Test
    public void testvalidateEntityFilterDTOValidALLNull() {

        entityFilterDTO.setCertificateAssigned(0);

        final boolean isvalid = dtoValidator.validateEntityFilterDTO(entityFilterDTO);
        assertEquals(true, isvalid);
    }

    @Test
    public void testvalidateEntityFilterDTOInValidStatus() {

        entityFilterDTO.setName("TestName");
        entityFilterDTO.setCertificateAssigned(1);

        type = new ArrayList<EntityType>();
        type.add(EntityType.CA_ENTITY);

        entityFilterDTO.setType(type);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();

        status.add(EntityStatus.INACTIVE);

        entityFilterDTO.setStatus(status);

        final boolean isvalid = dtoValidator.validateEntityFilterDTO(entityFilterDTO);
        assertNotEquals(false, isvalid);
    }

    @Test
    public void testNullName() {

        entityFilterDTO.setName(null);
        entityFilterDTO.setCertificateAssigned(1);
        type = new ArrayList<EntityType>();
        type.add(EntityType.CA_ENTITY);
        entityFilterDTO.setType(type);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();

        status.add(EntityStatus.ACTIVE);
        status.add(EntityStatus.INACTIVE);

        entityFilterDTO.setStatus(status);

        entityDTO.setFilter(entityFilterDTO);
        entityDTO.setId(2);
        entityDTO.setLimit(10);
        entityDTO.setOffset(5);
        entityDTO.setFilter(entityFilterDTO);

        assertFalse(dtoValidator.validateEntityFilterDTO(entityFilterDTO));

    }

    @Test
    public void testValidEntityDTO() {

        entityFilterDTO.setName(null);
        entityFilterDTO.setCertificateAssigned(null);
        type = new ArrayList<EntityType>();
        type.add(EntityType.CA_ENTITY);
        entityFilterDTO.setType(null);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();

        status.add(EntityStatus.ACTIVE);
        status.add(EntityStatus.INACTIVE);

        entityFilterDTO.setStatus(null);

        entityDTO.setFilter(entityFilterDTO);
        entityDTO.setId(2);
        entityDTO.setLimit(10);
        entityDTO.setOffset(5);

        entityDTO.setFilter(entityFilterDTO);

        assertTrue(dtoValidator.validateEntityFilterDTO(entityFilterDTO));

    }
}
