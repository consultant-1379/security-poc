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

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.profiles.api.ProfileConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;

public class AppProfileXmlConfigurationTest {

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration#getTrustProfilesInfo()} .
     */
    @Test
    public void testGetTrustProfilesInfo() {

        final File xmlPathTest = new File("src/test/resources/CAtrustProfile.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        assertTrue("Size of CAtrustProfile.xml is not correct (8)", profileConfigInfo.getTrustProfilesInfo().size() == 8);

        assertTrue("Profile(0) name not correct", profileConfigInfo.getTrustProfilesInfo().get(0).getName().equals("ENM PKI Root CA"));

        assertTrue("File path not correct", profileConfigInfo.getXmlFilePath().equals("src/test/resources/CAtrustProfile.xml"));

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration#getEntityProfilesInfo()} .
     */
    @Test
    public void testGetEntityProfilesInfo() {

        final File xmlPathTest = new File("src/test/resources/endEntityProfile.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        assertTrue("Size of endEntityProfile.xml is not correct (2)", profileConfigInfo.getEntityProfilesInfo().size() == 3);

        assertTrue("Profile(0) name not correct", profileConfigInfo.getEntityProfilesInfo().get(0).getName().equals("credMCLI_EP"));

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration#getCertificateProfilesInfo()} .
     */
    @Test
    public void testGetCertificateProfilesInfo() {

        final File xmlPathTest = new File("src/test/resources/certificateProfile.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        assertTrue("Size of certificateProfile.xml is not correct (1)", profileConfigInfo.getCertificateProfilesInfo().size() == 1);

        assertTrue("Profile(0) name not correct", profileConfigInfo.getCertificateProfilesInfo().get(0).getName().equals("credMCLI_CP"));

    }

}
