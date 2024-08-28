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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link EnumTypeSerializerWithoutId}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class EnumTypeSerializerWithoutIdTest {

	@Mock
	EnumTypeSerializerWithoutId EnumTypeSerializerWithoutId;

	SubjectAltNameFieldType subjectAltNameFieldType;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		mapper = new ObjectMapper();

		final SimpleModule module = new SimpleModule();

		module.addSerializer(
				com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType.class,
				new EnumTypeSerializerWithoutId<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType>());

		mapper.registerModule(module);

		subjectAltNameFieldType = SubjectAltNameFieldType.fromId(1);
	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testSerialize() throws JsonProcessingException {

		final String expectedOutput = "{\"type\":\"RFC822_NAME\",\"value\":\"\"}";
		final String jsonOutput = mapper.writeValueAsString(subjectAltNameFieldType);
		assertEquals(expectedOutput, jsonOutput);
	}
}
