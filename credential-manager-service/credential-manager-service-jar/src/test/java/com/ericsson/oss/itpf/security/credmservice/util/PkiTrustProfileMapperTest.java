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
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.profiles.api.ProfileConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public class PkiTrustProfileMapperTest {

    private static final String EPPKI_CA_NAME = "VC_Root_CA_A1";

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmservice.util.PkiTrustProfileMapper#ConvertTrustProfileFrom(com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlTrustProfile)}
     * .
     */
    @Test
    public void testConvertTrustProfileFrom1() {

        final File xmlPathTest = new File("src/test/resources/CAtrustProfile.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        TrustProfile trustProfile = null;
        try {
            trustProfile = PkiTrustProfileMapper.ConvertTrustProfileFrom(profileConfigInfo.getTrustProfilesInfo().get(1));
        } catch (final PkiProfileMapperException e) {

            e.printStackTrace();
        }
        final List<String> trustProfileList = new ArrayList<String>();
        trustProfileList.add(trustProfile.getTrustCAChains().get(0).getInternalCA().getCertificateAuthority().getName());
        trustProfileList.add(trustProfile.getTrustCAChains().get(1).getInternalCA().getCertificateAuthority().getName());
        
        System.out.println("truts 0"+trustProfileList.get(0));
        System.out.println("truts 1"+trustProfileList.get(1));

        assertTrue("trustProfile(0) doesn't match", trustProfileList.get(0).equals("CN=ENM PKI Root CA"));

        assertTrue("trustProfile(1) doesn't match", trustProfileList.get(1).equals("CN=ENM Infrastructure CA"));

        try {
            trustProfile = PkiTrustProfileMapper.ConvertTrustProfileFrom(null);
        } catch (final PkiProfileMapperException e) {

            assertTrue("Exception expected (null profile)", true);
        }
    }

    @Test
    public void testConvertTrustProfileFrom2() {

        final File xmlPathTest = new File("src/test/resources/ENM-Sub2-CA_TP.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        TrustProfile trustProfile = null;
        try {
            trustProfile = PkiTrustProfileMapper.ConvertTrustProfileFrom(profileConfigInfo.getTrustProfilesInfo().get(1));
        } catch (final PkiProfileMapperException e) {

            e.printStackTrace();
        }

        final List<String> trustProfileList = new ArrayList<String>();
        trustProfileList.add(trustProfile.getTrustCAChains().get(0).getInternalCA().getCertificateAuthority().getName());

        assertTrue("trustProfile(0) doesn't match", trustProfileList.get(0).equals("ENM OAM CA"));

    }

    @Test
    public void testConvertTrustProfileWithExternalCAs() {

        final File xmlPathTest = new File("src/test/resources/ENM-EPPKI_TP.xml");

        ProfileConfigInformation profileConfigInfo = null;
        try {
            profileConfigInfo = new AppProfileXmlConfiguration(xmlPathTest);

        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        assertTrue("profileConfigInfo is NULL", profileConfigInfo != null);

        TrustProfile trustProfile = null;
        try {
            trustProfile = PkiTrustProfileMapper.ConvertTrustProfileFrom(profileConfigInfo.getTrustProfilesInfo().get(0));
        } catch (final PkiProfileMapperException e) {

            e.printStackTrace();
        }

        final List<ExtCA> trustProfileExtCAList = trustProfile.getExternalCAs();

        assertEquals(1, trustProfileExtCAList.size());

        assertEquals(EPPKI_CA_NAME, trustProfileExtCAList.get(0).getCertificateAuthority().getName());

        final List<String> trustProfileInternalCAList = new ArrayList<String>();
        for(int i=0; i<trustProfile.getTrustCAChains().size(); i++) {
        	trustProfileInternalCAList.add(trustProfile.getTrustCAChains().get(i).getInternalCA().getCertificateAuthority().getName());
        }

        assertEquals(1, trustProfileInternalCAList.size());

    }
}
