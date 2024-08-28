/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import static org.junit.Assert.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameValueCommandResponse;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.setupdata.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

@RunWith(MockitoJUnitRunner.class)
public class EntityProfileViewCommandResponseTest {
    @Spy
    private Logger logger = LoggerFactory.getLogger(EntityProfileViewCommandResponse.class);
    @Mock
    CommandHandlerUtils commandHandlerUtils;
    @InjectMocks
    EntityProfileViewCommandResponse entityProfileViewCommandResponse;
    EntityProfile entityProfile;
    Profiles profiles;
    PkiNameValueCommandResponse pkiNameValueCommandResponse;

    /**
     * SetUp method for setting unit test dependency
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
    }

    @Test
    public void testBuildCommandResponseForEntityProfile() throws DatatypeConfigurationException {
        MockitoAnnotations.initMocks(entityProfileViewCommandResponse);
        EntityProfile entityProfile = new EntityProfile();
        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("ENM_Root_CP");
        entityProfile.setName("TestEntityProfile");
        entityProfile = profiles.getEntityProfiles().get(0);
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        final TrustProfile trustProfile = trustProfileSetUpData.getTrustProfileDataForEqual();
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();
        trustProfiles.add(trustProfile);
        entityProfile.setTrustProfiles(trustProfiles);
        entityProfile.setCertificateProfile(certificateProfile);
        pkiNameValueCommandResponse = entityProfileViewCommandResponse.buildCommandResponseForEntityProfile(entityProfile);
        assertNotNull(pkiNameValueCommandResponse);
    }

    @Test
    public void testBuildCommandResponseForEntityProfilewithNoTrustProfiles() throws DatatypeConfigurationException {
        MockitoAnnotations.initMocks(entityProfileViewCommandResponse);
        EntityProfile entityProfile = new EntityProfile();
        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("ENM_Root_CP");
        entityProfile.setName("TestEntityProfile");
        entityProfile = profiles.getEntityProfiles().get(0);
        entityProfile.setCertificateProfile(certificateProfile);
        pkiNameValueCommandResponse = entityProfileViewCommandResponse.buildCommandResponseForEntityProfile(entityProfile);
        assertNotNull(pkiNameValueCommandResponse);
    }
}
