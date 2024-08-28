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
 * Test class for {@link TrustProfileDeserializer}
 * 
 * @author tcspred
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileDeserializerTest {

	@Mock
	TrustProfileDeserializer trustProfileDeserializer;

	TrustProfile trustProfile;

	ObjectMapper mapper;

	@Before
	public void setUp() {

		mapper = new ObjectMapper();
		final SimpleModule module = new SimpleModule();

		module.addDeserializer(TrustProfile.class,
				new TrustProfileDeserializer());

		mapper.registerModule(module);

		trustProfile = new TrustProfile();

		trustProfile.setName("TestTrustProfile");

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

		final String inputJsonEntityCategory = "{\"id\":0,\"name\":\"TestTrustProfile\",\"active\":true,\"internalCAs\":[{\"isChainRequired\":true,\"CAEntity\":{\"id\":1,\"name\":\"TestIssuer\"}}]}";

		TrustProfile actualTrustProfile = mapper.readValue(
				inputJsonEntityCategory, TrustProfile.class);

		assertEquals(trustProfile.getId(), actualTrustProfile.getId());
		assertEquals(trustProfile.getName(), actualTrustProfile.getName());
		assertEquals(trustProfile.isActive(), actualTrustProfile.isActive());
		assertEquals(trustProfile.getTrustCAChains().get(0).isChainRequired(),
				actualTrustProfile.getTrustCAChains().get(0).isChainRequired());
		// assertEquals(trustProfile.getTrustCAChains().get(0).getInternalCA(),
		// actualTrustProfile.getTrustCAChains());

	}
}
