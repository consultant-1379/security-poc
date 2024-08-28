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
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link CertificateAuthoritySerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */
public class CertificateAuthoritySerializerTest {

	@Mock
	CertificateAuthoritySerializer certificateAuthoritySerializer;

	CertificateAuthority certificateAuthority;

	JsonGenerator generator;
	SerializerProvider provider;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(CertificateAuthority.class,
				new CertificateAuthoritySerializer());

		mapper.registerModule(module);

		certificateAuthority = new CertificateAuthority();
		certificateAuthority.setId(1);
		certificateAuthority.setName("TestCA");
		certificateAuthority.setStatus(CAStatus.ACTIVE);

		final Subject subject = new Subject();
		final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
		final SubjectField subjectField = new SubjectField();

		subjectField.setType(SubjectFieldType.COMMON_NAME);
		subjectField.setValue("ENM_Root");
		subjectFields.add(subjectField);

		subject.setSubjectFields(subjectFields);

		certificateAuthority.setSubject(subject);

		final SubjectAltName subjectAltName = new SubjectAltName();
		final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
		final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
		final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();

		subjectAltNameString.setValue("www.xyz.com");

		subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
		subjectAltNameField.setValue(subjectAltNameString);

		subjectAltNameFields.add(subjectAltNameField);

		subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

		certificateAuthority.setSubjectAltName(subjectAltName);

	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testCertificateAuthoritySerialize()
			throws JsonProcessingException, IOException {

		final String expectedJsonEntityCategory = "{\"id\":1,\"name\":\"TestCA\",\"active\":true,\"subject\":{\"subjectFields\":[{\"type\":\"COMMON_NAME\",\"value\":\"ENM_Root\"}]},\"subjectAltName\":{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"www.xyz.com\"}}]}}";

		final String jsonOutput = mapper.writeValueAsString(certificateAuthority);

		assertEquals(expectedJsonEntityCategory, jsonOutput);

	}

}
