/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;

@RunWith(MockitoJUnitRunner.class)
public class ProfilesModelMapperFactoryTest {
    @InjectMocks
    ProfileModelMapperFactory modelMapperFactory;

    @Mock
    TrustProfileMapper trustProfileMapper;

    @Mock
    CertificateProfileMapper certificateProfileMapper;

    @Mock
    EntityProfileMapper entityProfileMapper;

    @Test
    public void testTrustProfileMapper() {
        assertEquals(modelMapperFactory.getProfileModelMapper(ProfileType.TRUST_PROFILE), trustProfileMapper);
    }

    @Test
    public void testCertificateProfileMapper() {
        assertEquals(modelMapperFactory.getProfileModelMapper(ProfileType.CERTIFICATE_PROFILE), certificateProfileMapper);
    }

    @Test
    public void testEntityProfileMapper() {
        assertEquals(modelMapperFactory.getProfileModelMapper(ProfileType.ENTITY_PROFILE), entityProfileMapper);
    }

    @Test(expected = NullPointerException.class)
    public void testgetEntitiesMapperNull() {
        modelMapperFactory.getProfileModelMapper(null);
    }
}
