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
package com.ericsson.oss.itpf.security.pki.manager.rest.serializers;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

public class AbstractProfileFetchSerializerTest {

	@Mock
	AbstractProfileFetchSerializer abstractProfileFetchSerializer;

	AbstractProfile entityProfile, trustProfile, certificateProfile;
	
	JsonGenerator generator;
	SerializerProvider provider;

	ObjectMapper mapper;

	@Before
	public void setUp() {

	    abstractProfileFetchSerializer = new AbstractProfileFetchSerializer();
		
		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(AbstractProfile.class,
						new AbstractProfileFetchSerializer());

		mapper.registerModule(module);

		entityProfile = new EntityProfile();
		trustProfile = new TrustProfile();
		certificateProfile = new CertificateProfile();

		entityProfile.setId(1);
		entityProfile.setName("EntityProfileTest");
		entityProfile.setActive(true);
		entityProfile.setType(ProfileType.ENTITY_PROFILE);

		trustProfile.setId(2);
		trustProfile.setName("TrustProfileTest");

		certificateProfile.setId(3);
		certificateProfile.setName("CertificateProfileTest");
		certificateProfile.setActive(true);
		certificateProfile.setType(ProfileType.CERTIFICATE_PROFILE);

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

		final String expectedJsonEntityCategory = "{\"id\":1,\"type\":\"ENTITY_PROFILE\",\"name\":\"EntityProfileTest\",\"status\":\"active\"}";

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
	public void testCertificateProfileSerialize() throws JsonProcessingException,
			IOException {

		final String expectedJsonEntityCategory = "{\"id\":3,\"type\":\"CERTIFICATE_PROFILE\",\"name\":\"CertificateProfileTest\",\"status\":\"active\"}";
		
		final String jsonOutput = mapper.writeValueAsString(certificateProfile);
		
		assertEquals(expectedJsonEntityCategory, jsonOutput);
		
	}
	
	
}
