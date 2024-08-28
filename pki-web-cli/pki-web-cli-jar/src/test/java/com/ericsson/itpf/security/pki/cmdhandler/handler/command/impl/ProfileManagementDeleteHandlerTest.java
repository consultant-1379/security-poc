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

import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileInUseException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementDeleteHandlerTest {

    @InjectMocks
    ProfileManagementDeleteHandler profileManagementDeleteHandler;

    @Spy
    private Logger logger = LoggerFactory.getLogger(ProfileManagementDeleteHandler.class);

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;


    PkiPropertyCommand command;

    Profiles profiles = new Profiles();

    Map<String, Object> properties = new HashMap<String, Object>();
    List<AbstractEntity> entitiesList = new ArrayList<AbstractEntity>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "PROFILEMANAGEMENTDELETE");
        properties.put("profiletype", "entity");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.PROFILEMANAGEMENTDELETE);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        Mockito.when(eServiceRefProxy.getProfileManagementService()).thenReturn(profileManagementService);

    }

    @Test
    public void testProcessCommand_ProfileDeleteHandler() throws IOException {
        MockitoAnnotations.initMocks(profileManagementDeleteHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Profiles deleted successfully");
    }

    @Test
    public void testProcessCommand_ProfileDeleteHandler_ByNameAndType() {
        MockitoAnnotations.initMocks(profileManagementDeleteHandler);

        properties.remove("xmlfile");
        properties.put("name", "ENMServiceEntityProfile");

        when(commandHandlerUtils.getProfileType("entity")).thenReturn(ProfileType.ENTITY_PROFILE);
        when(commandHandlerUtils.getProfileInstance(ProfileType.ENTITY_PROFILE)).thenReturn(profiles.getEntityProfiles().get(0));

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("entity Profile with name ENMServiceEntityProfile successfully deleted"));
    }

    @Test
    public void testProcessCommand_ProfileDeleteHandler_Exception() throws IOException {
        MockitoAnnotations.initMocks(profileManagementDeleteHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(null);

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11102 Error while deleting null Profile Information is missing in the XML file");
    }

    @Test
    public void testProcessCommand_ProfileDeleteHandlerProfileInUseException() throws ProfileInUseException, IOException {
        MockitoAnnotations.initMocks(profileManagementDeleteHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenThrow(new ProfileInUseException());

        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Error: 11104 Error while deleting null"));
    }

    @Test
    public void test_ProfileDeleteHandler_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementDeleteHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(SecurityViolationException.class).when(profileManagementService).deleteProfiles(profiles);
        profileManagementDeleteHandler.process(command);

    }
    /*
     * @Test
     *
     * @Ignore public void testProcessCommand_ProfileDeleteHandler_InvalidProfileAttributeException() throws IOException { MockitoAnnotations.initMocks(profileManagementDeleteHandler);
     *
     * properties.put("xmlfile", profiles);
     *
     * when(commandHandlerUtils.getProfilesFromInputXml(command)).thenThrow(new InvalidProfileAttributeException());
     *
     * PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command); assertTrue(commandResponse.getMessage().contains(
     * "Error: 11106 Unexpected Internal Error, please check the error log for more details.Error while deleting")); }
     *
     * @Test
     *
     * @Ignore public void testProcessCommand_ProfileDeleteHandler_MissingMandatoryFieldException() throws IOException { MockitoAnnotations.initMocks(profileManagementDeleteHandler);
     *
     * properties.put("xmlfile", profiles);
     *
     * when(commandHandlerUtils.getProfilesFromInputXml(command)).thenThrow(new MissingMandatoryFieldException());
     *
     * PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command); assertTrue(commandResponse.getMessage().contains(
     * "Error: 11332 Unexpected Internal Error, please check the error log for more details.Error while deleting")); }
     *
     * @Test
     *
     * @Ignore public void testProcessCommand_ProfileDeleteHandler_ProfileNotFoundException() throws IOException { MockitoAnnotations.initMocks(profileManagementDeleteHandler);
     *
     * properties.put("xmlfile", profiles);
     *
     * when(commandHandlerUtils.getProfilesFromInputXml(command)).thenThrow(new ProfileNotFoundException());
     *
     * when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenThrow(new ProfileNotFoundException());
     *
     * PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command); assertTrue(commandResponse.getMessage().contains(
     * "Error: 11103 Error while deleting profiles")); }
     *
     * @Test
     *
     * @Ignore public void testProcessCommand_ProfileDeleteHandler_ProfileServiceException() throws IOException { MockitoAnnotations.initMocks(profileManagementDeleteHandler);
     *
     * properties.put("xmlfile", profiles);
     *
     * when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenThrow(new ProfileInUseException());
     *
     * PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command); assertTrue(commandResponse.getMessage().contains(
     * "Error: 11101 Unexpected Internal Error, please check the error log for more details.Error while deleting")); }
     *
     * @Test
     *
     * @Ignore public void testProcessCommand_ProfileDeleteHandler_commonRuntimeException() throws IOException { MockitoAnnotations.initMocks(profileManagementDeleteHandler);
     *
     * properties.put("xmlfile", profiles);
     *
     * when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenThrow(new CommonRuntimeException("xml format not valid"));
     *
     * PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command); assertEquals(commandResponse.getMessage(),
     * "Error: 11101 Invalid xml format found, Please see online help for correct xml formatError while deleting null xml format not valid"); }
     *
     * @Test
     *
     * @Ignore public void testProcessCommand_ProfileDeleteHandler_Exception() throws IOException { MockitoAnnotations.initMocks(profileManagementDeleteHandler);
     *
     * properties.put("xmlfile", profiles);
     *
     * when(commandHandlerUtils.getUpdatedProfilesFromInputXml(command)).thenThrow(new RuntimeException());
     *
     * PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) profileManagementDeleteHandler.process(command); assertEquals(commandResponse.getMessage(),
     * "Error: 11099 Error while deleting null null"); }
     */
}
