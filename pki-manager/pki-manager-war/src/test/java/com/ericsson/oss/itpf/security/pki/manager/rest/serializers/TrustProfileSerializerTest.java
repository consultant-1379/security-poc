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

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.TrustCAChainSetupData;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link rustProfileSerializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileSerializerTest {

	@Mock
	TrustProfileSerializer trustProfileSerializer;

	TrustProfile trustProfile;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addSerializer(TrustProfile.class, new TrustProfileSerializer());

		mapper.registerModule(module);

		trustProfile = new TrustProfile();

		TrustCAChainSetupData trustCAChainSetupData = new TrustCAChainSetupData();

		trustProfile.setTrustCAChains(trustCAChainSetupData.getTrustCAChains());
	}

	/**
	 * Method for Serialize()
	 * 
	 * @throws JsonProcessingException
	 *             , IOException
	 */
	@Test
	public void testSerialize() throws JsonProcessingException, IOException {

		final String expectedJsonTrustProfile = "{\"id\":0,\"name\":null,\"active\":true,\"internalCAs\":[{\"isChainRequired\":true,\"CAEntity\":{\"id\":1,\"name\":\"TestIssuer\"}}]}";

		final String jsonOutput = mapper.writeValueAsString(trustProfile);

		assertEquals(expectedJsonTrustProfile, jsonOutput);
		

	}

}
