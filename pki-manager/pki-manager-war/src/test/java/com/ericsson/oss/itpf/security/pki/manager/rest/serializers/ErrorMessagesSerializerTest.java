/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

/**
 * Test class for {@link ErrorMessagesSerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ErrorMessageDTO;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

@RunWith(MockitoJUnitRunner.class)
public class ErrorMessagesSerializerTest {

	@Mock
	ErrorMessagesSerializer errorMessagesSerializer;

	ErrorMessageDTO errorMessageDTO;

	JsonGenerator generator;
	SerializerProvider provider;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(ErrorMessageDTO.class,
				new ErrorMessagesSerializer());
		mapper.registerModule(module);

		errorMessageDTO = new ErrorMessageDTO();
		errorMessageDTO.setCode("100");
		errorMessageDTO.setMessage("Internal Exception occurred");
	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testSerialize() throws JsonProcessingException, IOException {

		final String expectedJsonEntityCategory = "{\"code\":100,\"message\":\"Internal Exception occurred\"}";

		errorMessagesSerializer.serialize(errorMessageDTO, generator, provider);

		final String jsonOutput = mapper.writeValueAsString(errorMessageDTO);

		assertEquals(expectedJsonEntityCategory, jsonOutput);

	}

}
