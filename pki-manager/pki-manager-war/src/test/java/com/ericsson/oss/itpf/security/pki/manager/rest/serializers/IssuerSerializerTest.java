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

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link IssuerSerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class IssuerSerializerTest {

	@Mock
	IssuerSerializer issuerSerializer;

	CAEntity caEntity;

	JsonGenerator generator;
	SerializerProvider provider;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(CAEntity.class, new IssuerSerializer());

		mapper.registerModule(module);

		caEntity = new CAEntity();

		final CertificateAuthority certificateAuthority = new CertificateAuthority();
		certificateAuthority.setName("TestInternalCA");
		certificateAuthority.setRootCA(true);
		certificateAuthority.setId(1);

		caEntity.setCertificateAuthority(certificateAuthority);
	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testSerialize() throws JsonProcessingException, IOException {

		final String expectedJsonEntityCategory = "{\"id\":1,\"name\":\"TestInternalCA\"}";

		issuerSerializer.serialize(caEntity, generator, provider);

		final String jsonOutput = mapper.writeValueAsString(caEntity);

		assertEquals(expectedJsonEntityCategory, jsonOutput);

	}
}
