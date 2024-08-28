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


import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link AbstractProfileSerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class AbstractProfileSerializerTest {

	@Mock
	AbstractProfileSerializer abstractProfileSerializer;

	AbstractProfile entityProfile, trustProfile, certificateProfile;

	JsonGenerator generator;
	SerializerProvider provider;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(AbstractProfile.class,
				new AbstractProfileSerializer());

		mapper.registerModule(module);

		entityProfile = new EntityProfile();
		trustProfile = new TrustProfile();
		certificateProfile = new CertificateProfile();

		entityProfile.setId(1);
		entityProfile.setName("EntityProfileTest");

		trustProfile.setId(2);
		trustProfile.setName("TrustProfileTest");

		certificateProfile.setId(3);
		certificateProfile.setName("CertificateProfileTest");

	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */

	@Test
	public void testEntityProfileSerialize() throws JsonProcessingException,
			IOException {

		final String expectedJsonEntityCategory = "{\"id\":1,\"name\":\"EntityProfileTest\"}";

		abstractProfileSerializer.serialize(entityProfile, generator, provider);

		final String jsonOutput = mapper.writeValueAsString(entityProfile);

		assertEquals(expectedJsonEntityCategory, jsonOutput);

	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testTrustProfileSerialize() throws JsonProcessingException,
			IOException {

		final String expectedJsonEntityCategory = "{\"id\":2,\"name\":\"TrustProfileTest\"}";

		abstractProfileSerializer.serialize(trustProfile, generator, provider);

		final String jsonOutput = mapper.writeValueAsString(trustProfile);

		assertEquals(expectedJsonEntityCategory, jsonOutput);
		
	}

}
