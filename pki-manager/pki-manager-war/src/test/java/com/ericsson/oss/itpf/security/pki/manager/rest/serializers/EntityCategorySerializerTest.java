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
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;

import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link EntityCategorySerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */

@RunWith(MockitoJUnitRunner.class)
public class EntityCategorySerializerTest {

	@Mock
	EntityCategorySerializer entityCategorySerializer;

	EntityCategory entityCategory;

	JsonGenerator generator;
	SerializerProvider provider;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		entityCategory = new EntityCategory();
		entityCategory.setId(1);
		entityCategory.setModifiable(true);
		entityCategory.setName("EndEntity");

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(EntityCategory.class,
				new EntityCategorySerializer());
		mapper.registerModule(module);
	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testSerialize() throws JsonProcessingException, IOException {

		final String expectedJsonEntityCategory = "{\"id\":1,\"name\":\"EndEntity\"}";

		entityCategorySerializer.serialize(entityCategory, generator, provider);

		final String jsonOutput = mapper.writeValueAsString(entityCategory);

		assertEquals(expectedJsonEntityCategory, jsonOutput);

	}

}
