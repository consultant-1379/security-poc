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
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
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
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

/**
 * Test Class for checking Unit test for ProfileManagementImportHandler Class
 *
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementImportHandlerTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(ProfileManagementImportHandlerTest.class);

    @InjectMocks
    ProfileManagementImportHandler profileManagementImportHandler;

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

    /**
     * SetUp method for setting unittest dependency
     *
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "ENTITYMANAGEMENTIMPORT");
        properties.put("entitytype", "ca");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYMANAGEMENTIMPORT);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("entities.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        properties.put("xmlfile", profiles);
        Mockito.when(eServiceRefProxy.getProfileManagementService()).thenReturn(profileManagementService);


    }

    /**
     * Test for checking successful bulk profile import
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommand_ProfileImportHandler() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), Constants.BULK_SUCCESSFUL_INFO);
    }

    /**
     * Test for checking if input xml does not contains any profile information
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommand_ProfileImportHandler_NullEntities() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(null);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), Constants.NO_PROFILES_FOUND);
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_Exception() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new IllegalArgumentException("Inappropriate argument")).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage().toString(), "Error: 11099 Unexpected Internal Error, please check the error log for more details.Inappropriate argument");
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_AlgorithmNotFoundException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new AlgorithmNotFoundException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Provided Algorithm not found, Please check online help for the list of supported algorithms."));
    }

    /**
     * Test for checking if profile already exists in the system
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommand_ProfileImportHandler_ProfileExists() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new ProfileAlreadyExistsException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11104 Invalid Argument Profile already exists, Try with diferent name"));
    }

    /**
     * Test for checking if dependency is not satisfied i.e CA does not exist
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommand_ProfileImportHandler_CANotFound() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new CANotFoundException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11107"));
    }

    /**
     * Test for checking behavior incase of InternalServiceException occurs
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommand_ProfileImportHandler_CertificateExtensionException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new CertificateExtensionException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11340"));
    }

    /**
     * Test for checking behavior incase of IllegalArgumentException occurs
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommand_ProfileImportHandler_EntityCategoryNotFoundException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new EntityCategoryNotFoundException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11211"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_InvalidCAException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new InvalidCAException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11222"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_InvalidEntityCategoryException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new InvalidEntityCategoryException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11214"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_InvalidProfileAttributeException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new InvalidProfileAttributeException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11106"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_InvalidSubjectException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new InvalidSubjectException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11334"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_MissingMandatoryFieldException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new MissingMandatoryFieldException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11332"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_ProfileNotFoundException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new ProfileNotFoundException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11103"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_ProfileServiceException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new ProfileServiceException()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11101"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_UnSupportedCertificateVersion() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new UnSupportedCertificateVersion()).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11331"));
    }

    @Test
    public void testProcessCommand_ProfileImportHandler_CommonRuntimeException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new CommonRuntimeException(null)).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementImportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11101 Invalid xml format found, Please see online help for correct xml format"));
    }

    @Test
    public void test_ProfileImportHandler_SecurityViolationException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementImportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(SecurityViolationException.class).when(profileManagementService).importProfiles((Profiles) Mockito.anyObject());
        profileManagementImportHandler.process(command);
    }

}
