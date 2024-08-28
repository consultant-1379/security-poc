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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.*;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementViewHandlerTest {
    @Spy
    private Logger logger = LoggerFactory.getLogger(ProfileManagementViewHandler.class);;
    @InjectMocks
    ProfileManagementViewHandler profileManagementViewHandler;
    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    CertificateProfileViewCommandResponse certificateProfileViewCommandResponse;

    @Mock
    EntityProfileViewCommandResponse entityProfileViewCommandResponse;

    @Mock
    TrustProfileViewCommandResponse trustProfileViewCommandResponse;

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    Profiles profiles;

    final Map<String, Object> properties = new HashMap<String, Object>();

    final PkiNameValueCommandResponse commandResponse = new PkiNameValueCommandResponse();

    /**
     * SetUp method for setting unit test dependency
     *
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "PROFILEMANAGEMENTVIEW");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.PROFILEMANAGEMENTVIEW);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        Mockito.when(eServiceRefProxy.getProfileManagementService()).thenReturn(profileManagementService);

    }

    /**
     * Test case for viewing All certificate profile
     */
    @Test
    public void testProcess_CertificateProfileViewHandler_AllSuccess() {
        properties.put("profiletype", "certificate");
        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("TestCertProfile");
        certificateProfile = profiles.getCertificateProfiles().get(0);
        Mockito.when(certificateProfileViewCommandResponse.buildCommandResponseForCertificateProfile(Mockito.any(CertificateProfile.class))).thenReturn(commandResponse);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.getProfile(profiles.getCertificateProfiles().get(0))).thenReturn(profiles.getCertificateProfiles().get(0));
        final PkiCommandResponse pkiCommandResponse = profileManagementViewHandler.process(command);
        assertNotNull(pkiCommandResponse);
    }

    /**
     * Test case for viewing All Entity profile
     */
    @Test
    public void testProcess_EntityProfileViewHandler_AllSuccess() {
        EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName("TestEntityProfile");
        properties.put("profiletype", "entity");
        entityProfile = profiles.getEntityProfiles().get(0);
        Mockito.when(entityProfileViewCommandResponse.buildCommandResponseForEntityProfile(Mockito.any(EntityProfile.class))).thenReturn(commandResponse);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.ENTITY_PROFILE);
        Mockito.when(commandHandlerUtils.getProfileInstance(ProfileType.ENTITY_PROFILE)).thenReturn(profiles.getEntityProfiles().get(0));
        Mockito.when(profileManagementService.getProfile(profiles.getEntityProfiles().get(0))).thenReturn(profiles.getEntityProfiles().get(0));
        final PkiCommandResponse pkiCommandResponse = profileManagementViewHandler.process(command);
        assertNotNull(pkiCommandResponse);
    }

    /**
     * Test case for viewing All Trust profile
     */

    @Test
    public void testProcess_TrustProfileViewHandler_AllSuccess() {
        final TrustProfile trustProfile = new TrustProfile();
        trustProfile.setName("TestTrustProfile");
        properties.put("profiletype", "trust");
        Mockito.when(trustProfileViewCommandResponse.buildCommandResponseForTrustProfile(Mockito.any(TrustProfile.class))).thenReturn(commandResponse);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.TRUST_PROFILE);
        Mockito.when(commandHandlerUtils.getProfileInstance(ProfileType.TRUST_PROFILE)).thenReturn(trustProfile);
        Mockito.when(profileManagementService.getProfile(trustProfile)).thenReturn(trustProfile);
        final PkiCommandResponse pkiCommandResponse = profileManagementViewHandler.process(command);
        assertNotNull(pkiCommandResponse);
    }

    @Test
    public void testProcess_TrustProfileViewHandler_All() {
        final TrustProfile trustProfile = new TrustProfile();
        trustProfile.setName("TestTrustProfile");
        properties.put("profiletype", "trust");
        properties.put("all", "");
        Mockito.when(trustProfileViewCommandResponse.buildCommandResponseForTrustProfile(Mockito.any(TrustProfile.class))).thenReturn(commandResponse);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.TRUST_PROFILE);
        Mockito.when(commandHandlerUtils.getProfileInstance(ProfileType.TRUST_PROFILE)).thenReturn(trustProfile);
        Mockito.when(profileManagementService.getProfile(trustProfile)).thenReturn(trustProfile);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementViewHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11001 Command syntax error : ProfileType ALL is not supported"));
    }

    @Test
    public void test_CertificateProfileViewHandler_SecurityViolationException() {
        properties.put("profiletype", "certificate");
        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("TestCertProfile");
        certificateProfile = profiles.getCertificateProfiles().get(0);
        //        Mockito.when(certificateProfileViewCommandResponse.buildCommandResponseForCertificateProfile(Mockito.any(CertificateProfile.class))).thenReturn(commandResponse);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.getProfile(profiles.getCertificateProfiles().get(0))).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        profileManagementViewHandler.process(command);
    }
    @Test
    public void testProcess_TrustProfileViewHandler_ProfileNotFoundException() {
        TrustProfile trustProfile = new TrustProfile();
        trustProfile.setName("TestTrustProfile");
        properties.put("profiletype", "trust");
        properties.put("all", "");

        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.TRUST_PROFILE);
        Mockito.when(commandHandlerUtils.getProfileInstance(ProfileType.TRUST_PROFILE)).thenReturn(trustProfile);
        Mockito.when(profileManagementService.getProfile(trustProfile)).thenReturn(trustProfile);
        Mockito.when(trustProfileViewCommandResponse.buildCommandResponseForTrustProfile(Mockito.any(TrustProfile.class))).thenThrow(new ProfileNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementViewHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("ProfileType ALL is not supported"));
    }
}
