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
package com.ericsson.oss.itpf.security.credmservice.profiles.impl;

import static org.junit.Assert.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;



public class SpecificProfilesListsTest {

	
	private List<AppProfileXmlConfiguration> prepareProfiles(){
	
		List<AppProfileXmlConfiguration> appProfXConfList = new ArrayList<AppProfileXmlConfiguration>();

		
		AppProfileXmlConfiguration profileConfigInfo1 = null;
		AppProfileXmlConfiguration profileConfigInfo2 = null;
		AppProfileXmlConfiguration profileConfigInfo3 = null;
		
		final File xmlPathTest1 = new File("src/test/resources/CAtrustProfile.xml");
		final File xmlPathTest2 = new File("src/test/resources/certificateProfile.xml");
		final File xmlPathTest3 = new File("src/test/resources/endEntityProfile.xml");

        try {
        	profileConfigInfo1 = new AppProfileXmlConfiguration(xmlPathTest1);
        	profileConfigInfo2 = new AppProfileXmlConfiguration(xmlPathTest2);
        	profileConfigInfo3 = new AppProfileXmlConfiguration(xmlPathTest3);
        	appProfXConfList.add( profileConfigInfo1);
        	appProfXConfList.add( profileConfigInfo2);
        	appProfXConfList.add( profileConfigInfo3);
        } catch (final CredentialManagerProfilesException e) {
            e.printStackTrace();
        }
                
        return appProfXConfList;
	}
	
		
	/**
	 * Test method for {@link com.ericsson.oss.itpf.security.credmservice.profiles.impl.SpecificProfilesLists#splitIntoSpecificLists(java.util.List)}.
	 */
	@Test
	public void testSplitIntoSpecificLists() {
		
		final SpecificProfilesLists genericProfilesList = new SpecificProfilesLists();
			
		genericProfilesList.splitIntoSpecificLists(prepareProfiles());

		assertTrue("TrustProfile List EMPTY", !genericProfilesList.getTrustProfilesList().isEmpty());			
		
		assertTrue("CertificateProfile List EMPTY",  !genericProfilesList.getCertificateProfilesList().isEmpty());
		
		assertTrue("EntityProfile List EMPTY",  !genericProfilesList.getEntityProfilesList().isEmpty());

	}
}
