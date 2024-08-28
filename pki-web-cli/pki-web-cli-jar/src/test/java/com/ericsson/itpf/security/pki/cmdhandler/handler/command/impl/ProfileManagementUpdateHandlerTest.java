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


import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementUpdateHandlerTest {

    @InjectMocks
    ProfileManagementUpdateHandler profileManagementUpdateHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    Logger logger = LoggerFactory.getLogger(ProfileManagementUpdateHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;
    Profiles profiles = new Profiles();
    List<AbstractProfile> profilesList = new ArrayList<AbstractProfile>();
    Map<String, Object> properties = new HashMap<String, Object>();

    @Before
    public void setUp() throws Exception {

        properties.put("command", "PROFILEMANAGEMENTUPDATE");
        properties.put("entitytype", "ca");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.PROFILEMANAGEMENTUPDATE);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("singleprofile.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        properties.put("xmlfile", profiles);
        properties.put("filePath", url.getPath());

        profilesList.add(profiles.getCertificateProfiles().get(0));
        Mockito.when(eServiceRefProxy.getProfileManagementService()).thenReturn(profileManagementService);

    }

    @Test
    public void testProcessCommandProfileUpdateHandler() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);

        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(profilesList);

        when(profileManagementService.updateProfile(profilesList.get(0))).thenReturn(profilesList.get(0));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "CertificateProfile ID: 0, Name: RootCA_Cert_Profile is sucessfully updated");
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerMultipleProfiles() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        profilesList.add(profiles.getCertificateProfiles().get(0));

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);

        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(profilesList);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Profiles updated successfully");
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerNoXml() {

        MockitoAnnotations.initMocks(profileManagementUpdateHandler);
        properties.remove("xmlfile");
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11101 Input xml file is missing");
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerNullProfiles() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(null);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.NO_PROFILE_FOUND_IN_XML);
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerProfileNotFound() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);
        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new ProfileNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11103 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerProfileAlreadyExists() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new ProfileAlreadyExistsException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11102 Invalid Argument Profile already exists, Try with diferent name");
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerCaNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new CANotFoundException("CA not found, Try with existing CA"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11221 CA not found, Try with existing CA");
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerIllegalArgumentException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new IllegalArgumentException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11101 This is an unexpected system error, please check the error log for more details. null");
    }

    @Test
    @Ignore
    public void testProcessCommandProfileUpdateHandlerProfileServiceException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new ProfileServiceException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11101 Invalid xml format found, Please see online help for correct xml format ");
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerProfileServiceExceptionProfileModifiableFlag() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new ProfileServiceException("Profile modifiable flag is disabled!!"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Profile modifiable flag is disabled!!");
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerCommonRuntimeException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new CommonRuntimeException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11101 Invalid xml format found, Please see online help for correct xml format ");
    }

    @Test
    public void testProfileUpdateHandler_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);

        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(profilesList);

        when(profileManagementService.updateProfile(profilesList.get(0))).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        profileManagementUpdateHandler.process(command);
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerAlgorithmNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new AlgorithmNotFoundException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11411 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerCertificateExtensionException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new CertificateExtensionException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11340 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerEntityCategoryNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new EntityCategoryNotFoundException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11211 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerInvalidCAException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new InvalidCAException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11222 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerInvalidEntityCategoryException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new InvalidEntityCategoryException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11214 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerInvalidProfileException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new InvalidProfileException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11105 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerInvalidProfileAttributeException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new InvalidProfileAttributeException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11106 "));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerInvalidSubjectException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new InvalidSubjectException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11334"));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerUnSupportedCertificateVersion() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new UnSupportedCertificateVersion());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11331"));
    }

    @Test
    public void testProcessCommandProfileUpdateHandlerMissingMandatoryFieldException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementUpdateHandler);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        when(commandHandlerUtils.getAllProfiles(Mockito.anyList(), Mockito.anyList(), Mockito.anyList())).thenReturn(profilesList);

        when(profileManagementService.updateProfile((AbstractProfile) Mockito.anyObject())).thenThrow(new MissingMandatoryFieldException());
        PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementUpdateHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11332 "));
    }
}
