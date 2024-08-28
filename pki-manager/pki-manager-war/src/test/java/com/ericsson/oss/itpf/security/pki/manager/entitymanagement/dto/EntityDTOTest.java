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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;

/**
 * Test class for {@link EntityDTO}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityDTOTest {

	EntityDTO entityDTO;
	EntityFilterDTO entityFilterDTO;

	@Before
	public void setUp() {

		entityFilterDTO = new EntityFilterDTO();
		entityFilterDTO.setName("TestName");
		entityFilterDTO.setCertificateAssigned(1);

		final List<EntityStatus> status = new ArrayList<EntityStatus>();
		entityFilterDTO.setStatus(status);

		entityDTO = new EntityDTO();

		entityDTO.setFilter(entityFilterDTO);
		entityDTO.setId(2);
		entityDTO.setLimit(10);
		entityDTO.setOffset(5);

		entityDTO.setFilter(entityFilterDTO);
		
		entityDTO.hashCode();
		entityDTO.toString();
	}

	/**
	 * Method for testing EntityDTO()
	 * 
	 * 
	 */
	@Test
	public void testEntityDTO() {
		

		assertEquals(2, entityDTO.getId());
		assertEquals(10, entityDTO.getLimit());
		assertEquals(5, entityDTO.getOffset());
		assertEquals("TestName", entityDTO.getFilter().getName());
		assertEquals(1, entityDTO.getFilter().getCertificateAssigned().intValue());
		

	}

	@Test
	public void testEntityDTOEquality() {

		final EntityDTO expectedEntityDTO = new EntityDTO();

		expectedEntityDTO.setFilter(entityFilterDTO);
		expectedEntityDTO.setId(2);
		expectedEntityDTO.setLimit(10);
		expectedEntityDTO.setOffset(5);

		expectedEntityDTO.setFilter(entityFilterDTO);

		final boolean equals = expectedEntityDTO.equals(entityDTO);

		assertEquals(true, equals);

		assertEquals(expectedEntityDTO, entityDTO);

	}

	@Test
	public void testEntityDTOEqual() {

		final EntityDTO expectedEntityDTO = entityDTO;

		expectedEntityDTO.setFilter(entityFilterDTO);
		expectedEntityDTO.setId(2);
		expectedEntityDTO.setLimit(10);
		expectedEntityDTO.setOffset(5);

		expectedEntityDTO.setFilter(entityFilterDTO);

		final boolean equals = expectedEntityDTO.equals(entityDTO);

		assertEquals(true, equals);

		assertEquals(expectedEntityDTO, entityDTO);

	}
}
