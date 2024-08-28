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

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link KeyGenerationAlgorithmSerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class KeyGenerationAlgorithmSerializerTest {

	@Mock
	KeyGenerationAlgorithmSerializer keyGenerationAlgorithmSerializer;

	ObjectMapper mapper;

	Algorithm algorithm;

	@Before
	public void setUp() throws IOException {

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(Algorithm.class,
				new KeyGenerationAlgorithmSerializer());

		mapper.registerModule(module);

		algorithm = new Algorithm();
		algorithm.setId(1);
		algorithm.setName("TestRSA");
		algorithm.setKeySize(1024);

	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testSerialize() throws JsonProcessingException, IOException {

		final String expectedJsonEntityCategory = "{\"id\":1,\"name\":\"TestRSA\",\"keySize\":1024}";

		final String jsonOutput = mapper.writeValueAsString(algorithm);

		assertEquals(expectedJsonEntityCategory, jsonOutput);

	}

}
