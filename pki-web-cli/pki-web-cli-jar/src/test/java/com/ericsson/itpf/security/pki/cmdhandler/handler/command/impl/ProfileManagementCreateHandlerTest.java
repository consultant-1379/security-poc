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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.Mockito;
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
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

/**
 * Test Class for checking Unit test for ProfileManagementCreateHandler Class
 *
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementCreateHandlerTest {

    @InjectMocks
    ProfileManagementCreateHandler profileManagementCreateHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    private Logger logger = LoggerFactory.getLogger(ProfileManagementCreateHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;
    Profiles profiles = new Profiles();

    Map<String, Object> properties = new HashMap<String, Object>();
    List<AbstractProfile> profilesList = new ArrayList<AbstractProfile>();

    /**
     * SetUp method for setting unittest dependency
     *
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "PROFILEMANAGEMENTCREATE");
        properties.put("profiletype", "ca");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.PROFILEMANAGEMENTCREATE);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        Mockito.when(eServiceRefProxy.getProfileManagementService()).thenReturn(profileManagementService);

    }

    /**
     * Test for checking successful profile creation
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommand() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));

        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(profilesList);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), Constants.PROFILES_GOT_CREATED_SUCCESSFULLY);
    }

    /**
     * Test for checking profile creation with multiple profiles
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommandMultipleProfiles() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        profilesList.add(profiles.getEntityProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(profilesList);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11101 Invalid xml format found, Please see online help for correct xml format");
    }

    /**
     * Test for checking profile creation when input xml file is missing
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommandNoXml() {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);
        properties.remove("xmlfile");
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11103 Input xml file is missing");

    }

    /**
     * Test for checking profile creation when profile information is missing in input xml
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommandNullEntities() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(null);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11103 Profile Information is missing in the XML file");
    }

    /**
     * Test for checking profile creation when NPE occurs
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommandRunTimeException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new NullPointerException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11099 Unexpected Internal Error, please check the error log for more details."));
    }

    @Test
    public void testProcessCommandAlgorithmNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new AlgorithmNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Provided Algorithm not found, Please check online help for the list of supported algorithms."));
    }

    /**
     * Test for checking profile creation when profile already exist
     *
     * @throws IOException
     */

    @Test
    public void testProcessCommandProfileAlreadyExists() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new ProfileAlreadyExistsException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11104 Invalid Argument Profile already exists, Try with diferent name"));
    }

    @Test
    public void testProcessCommandCANotFoundException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new CANotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11107"));
    }

    @Test
    public void testProcessCommandCertificateExtensionException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new CertificateExtensionException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11340"));
    }

    @Test
    public void testProcessCommandEntityCategoryNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new EntityCategoryNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11211"));
    }

    @Test
    public void testProcessCommandEntityInvalidCAException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new InvalidCAException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11222"));
    }

    @Test
    public void testProcessCommandEntityInvalidEntityCategoryException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new InvalidEntityCategoryException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11214"));
    }

    @Test
    public void testProcessCommandEntityInvalidProfileAttributeException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new InvalidProfileAttributeException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11106"));
    }

    @Test
    public void testProcessCommandEntityInvalidSubjectException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new InvalidSubjectException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11334"));
    }

    @Test
    public void testProcessCommandEntityMissingMandatoryFieldException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new MissingMandatoryFieldException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11332"));
    }

    @Test
    public void testProcessCommandEntityProfileNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new ProfileNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11103"));
    }

    @Test
    public void testProcessCommandEntityProfileServiceException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new ProfileServiceException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11101"));
    }

    @Test
    public void testProcessCommandEntityUnSupportedCertificateVersion() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new UnSupportedCertificateVersion());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11331"));
    }

    @Test
    public void testProcessCommandEntityCommonRuntimeException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new CommonRuntimeException(null));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11101 Invalid xml format found, Please see online help for correct xml format"));
    }

    /**
     * Test for checking entity profile creation when ca does not exist
     *
     * @throws IOException
     */
    @Test
    @Ignore
    public void testProcessCommandCANotFound() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new CANotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11107 CA not found CA not found ");
    }

    /**
     * Test for checking entity profile creation if input xml format is wrong
     *
     * @throws IOException
     */
    @Test
    public void testProcessCommandCommonRuntimeException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenThrow(new CommonRuntimeException("xml invalid"));

        profilesList.add(profiles.getCertificateProfiles().get(0));
        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenThrow(new CANotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementCreateHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11101 Invalid xml format found, Please see online help for correct xml format");
    }

    @Test
    public void testProcessCommand_SecurityViolationException() throws IOException {
        MockitoAnnotations.initMocks(profileManagementCreateHandler);

        properties.put("xmlfile", profiles);

        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        profilesList.add(profiles.getCertificateProfiles().get(0));

        when(commandHandlerUtils.getAllProfiles(profiles.getCertificateProfiles(), profiles.getEntityProfiles(), profiles.getTrustProfiles())).thenReturn(profilesList);
        when(profileManagementService.createProfile(profiles.getCertificateProfiles().get(0))).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        profileManagementCreateHandler.process(command);
    }

}
