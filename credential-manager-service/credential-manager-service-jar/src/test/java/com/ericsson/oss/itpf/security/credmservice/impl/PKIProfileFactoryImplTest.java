/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.api.PKIProfileFactory;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

@RunWith(MockitoJUnitRunner.class)
public class PKIProfileFactoryImplTest {

    PKIProfileFactory pkiProfileFactory;

    @Before
    public void setUp() {
        pkiProfileFactory = new PKIProfileFactoryImpl();
    }

    @Test
    public void testBuildForRequestByNameAndEntityProfile() throws CredentialManagerServiceException {

        pkiProfileFactory.setName("entityProfileName");
        pkiProfileFactory.setProfileType(ProfileType.ENTITY_PROFILE);
        final AbstractProfile profile = pkiProfileFactory.buildForRequest();

        assertNotNull(profile);
        assertEquals(EntityProfile.class, profile.getClass());
        assertEquals("entityProfileName", profile.getName());
    }

    @Test
    public void testBuildForRequestByNameAndCertificateProfile() throws CredentialManagerServiceException {

        pkiProfileFactory.setName("certificateProfileName");
        pkiProfileFactory.setProfileType(ProfileType.CERTIFICATE_PROFILE);
        final AbstractProfile profile = pkiProfileFactory.buildForRequest();

        assertNotNull(profile);
        assertEquals(CertificateProfile.class, profile.getClass());
        assertEquals("certificateProfileName", profile.getName());
    }

    @Test
    public void testBuildForRequestById() throws CredentialManagerServiceException {

        pkiProfileFactory.setId(7777);
        pkiProfileFactory.setProfileType(ProfileType.ENTITY_PROFILE);
        final AbstractProfile profile = pkiProfileFactory.buildForRequest();

        assertNotNull(profile);
        assertEquals(EntityProfile.class, profile.getClass());
        assertEquals(7777, profile.getId());
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForRequestWithNameEmpty() throws CredentialManagerServiceException {

        pkiProfileFactory.setName("");
        pkiProfileFactory.setProfileType(ProfileType.ENTITY_PROFILE);
        pkiProfileFactory.buildForRequest();
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForRequestWithNameAndIdNull() throws CredentialManagerServiceException {

        pkiProfileFactory.setProfileType(ProfileType.ENTITY_PROFILE);
        pkiProfileFactory.buildForRequest();
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForRequestWithoutProfileType() throws CredentialManagerServiceException {

        pkiProfileFactory.setName("entityProfileName");
        pkiProfileFactory.buildForRequest();
    }

    @Test
    public void testBuildTrustProfile() throws CredentialManagerServiceException {

        pkiProfileFactory.setName("trustProfileName");
        pkiProfileFactory.setProfileType(ProfileType.TRUST_PROFILE);
        final AbstractProfile profile = pkiProfileFactory.buildForRequest();

        assertNotNull(profile);
    }

}
