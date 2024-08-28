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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.net.URL;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameMultipleValueCommandResponse.Entry;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

/**
 * Test Class for checking Unit test for ProfileManagementListHandler Class
 *
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementListHandlerTest {

    @Spy
    private Logger logger = LoggerFactory.getLogger(ProfileManagementListHandler.class);;

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @InjectMocks
    ProfileManagementListHandler profileManagementListHandler;

    @Mock
    CliUtil cliUtil;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    List<String> validCommands;
    List<String> invalidCommands;
    Profiles profiles;

    /**
     * SetUp method for setting unittest dependency
     *
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("command", "PROFILEMANAGEMENTLIST");
        properties.put("profiletype", "certificate");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.PROFILEMANAGEMENTLIST);
        command.setProperties(properties);

        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        Mockito.when(eServiceRefProxy.getProfileManagementService()).thenReturn(profileManagementService);

    }

    /**
     * Test case for listing All certificate profile
     */
    @Test
    public void testProcess_ProfileListHandler_AllSuccess() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        final List<? extends AbstractProfile> abstractProfile = profiles.getCertificateProfiles();
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        Mockito.when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(
                (List<AbstractProfile>) abstractProfile);
        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) profileManagementListHandler.process(command);
        assertEquals(commandResponse.getAdditionalInformation(), Constants.LIST_OF_PROFILES);
    }

    /**
     * Test case for listing All trust profile
     */
    @Test
    public void testProcess_ProfileListHandler_TPSuccess() {
        command.getProperties().put("profiletype", "trust");
        MockitoAnnotations.initMocks(profileManagementListHandler);
        final List<? extends AbstractProfile> abstractProfile = profiles.getCertificateProfiles();
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.TRUST_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        Mockito.when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(
                (List<AbstractProfile>) abstractProfile);
        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) profileManagementListHandler.process(command);
        final Iterator<Entry> it = commandResponse.iterator();
        final Entry entry = it.next();
        assertEquals(entry.getName(), Constants.ID);
        assertEquals(entry.getValues()[0], Constants.PROFILE_NAME);
    }

    /**
     * Test case for listing All entity profile
     */
    @Test
    public void testProcess_ProfileListHandler_EPSuccess() {

        final List<AbstractProfile> profilesList = new ArrayList<AbstractProfile>();
        profilesList.add(profiles.getEntityProfiles().get(0));

        command.getProperties().put("profiletype", "entity");
        command.getProperties().put("name", "entityprofile");
        MockitoAnnotations.initMocks(profileManagementListHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.ENTITY_PROFILE);
        Mockito.when(profileManagementService.getProfile(profiles.getEntityProfiles().get(0))).thenReturn(profiles.getEntityProfiles().get(0));
        Mockito.when(commandHandlerUtils.getProfileInstance(ProfileType.ENTITY_PROFILE)).thenReturn(profiles.getEntityProfiles().get(0));
        Mockito.when(commandHandlerUtils.setProfiles(ProfileType.ENTITY_PROFILE, profilesList)).thenReturn(profiles);
        Mockito.when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(profilesList);

        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) profileManagementListHandler.process(command);
        final Iterator<Entry> it = commandResponse.iterator();
        Entry entry = it.next();
        assertEquals(entry.getName(), Constants.ID);
        assertEquals(entry.getValues()[0], Constants.PROFILE_NAME);
        entry = it.next();
        assertEquals(entry.getName(), "0");
        assertEquals(entry.getValues()[0], ProfileType.ENTITY_PROFILE.toString().replaceAll("_", "").toLowerCase());
    }

    /**
     * Test case for listing All certificate profile
     */
    @Test
    public void testProcess_ProfileListHandler_CPSuccess() {

        final List<? extends AbstractProfile> abstractProfile = profiles.getCertificateProfiles();

        command.getProperties().put("profiletype", "certificate");
        MockitoAnnotations.initMocks(profileManagementListHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        Mockito.when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(
                (List<AbstractProfile>) abstractProfile);
        final PkiNameMultipleValueCommandResponse commandResponse = (PkiNameMultipleValueCommandResponse) profileManagementListHandler.process(command);
        final Iterator<Entry> it = commandResponse.iterator();
        final Entry entry = it.next();
        assertEquals(entry.getName(), Constants.ID);
        assertEquals(entry.getValues()[0], Constants.PROFILE_NAME);
    }

    /**
     * Test case for list profile in case of InternalServiceException
     */
    @Test
    public void testProcess_ProfileListHandler_ProfileNotFoundException() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);

        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new ProfileNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11106 No profile found with matching criteria"));
    }

    /**
     * Test case for list profile in case of ProfileNotFoundException
     */
    @Test
    public void testProcess_ProfileListHandler_InvalidProfileAttributeException() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new InvalidProfileAttributeException("Invalid Profile Attribute"));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Invalid Profile Attribute"));
    }

    @Test
    public void testProcess_ProfileListHandler_ProfileServiceException() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new ProfileServiceException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Suggested Solution :  retry "));

    }

    @Test
    public void testProcess_ProfileListHandler_MissingMandatoryFieldException() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new MissingMandatoryFieldException("Invalid Version"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Invalid Version"));
    }

    @Test
    public void testProcess_ProfileListHandler_IllegalArgumentException() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new IllegalArgumentException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11102 Unsupported PKI command argument"));
    }

    /**
     * Test case for list profile in case of ALL category
     */
    @Test
    public void testProcess_ProfileListHandler_CommandAll() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        final List<? extends AbstractProfile> abstractProfile = profiles.getCertificateProfiles();
        command.getProperties().put("all", "all");
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        Mockito.when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(
                (List<AbstractProfile>) abstractProfile);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementListHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11001 Command syntax error : ProfileType ALL is not supported");
    }

    /**
     * Test case for list profile in case of Service returns NULL
     */
    @Test
    public void testProcess_ProfileListHandler_ReturnNullProfilesForResponse() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        command.getProperties().put("all", "all");
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(null);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementListHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11001 Command syntax error : ProfileType ALL is not supported");
    }

    @Test
    public void test_ProfileListHandler_SecurityViolationException() {
        MockitoAnnotations.initMocks(profileManagementListHandler);
        final List<? extends AbstractProfile> abstractProfile = profiles.getCertificateProfiles();
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(profileManagementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        profileManagementListHandler.process(command);
    }
}
