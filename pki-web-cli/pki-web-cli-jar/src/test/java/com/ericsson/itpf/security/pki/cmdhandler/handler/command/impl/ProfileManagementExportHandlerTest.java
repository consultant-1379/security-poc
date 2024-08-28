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

import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URL;
import java.util.*;

import org.antlr.v4.runtime.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.itpf.security.pki.parser.PkiLexer;
import com.ericsson.itpf.security.pki.parser.PkiParser;

import org.mockito.runners.MockitoJUnitRunner;

/**
 * Test Class for checking Unit test for ProfileManagementImportHandler Class
 *
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfileManagementExportHandlerTest {

    List<String> validCommands;
    List<String> invalidCommands;
    PkiPropertyCommand command;
    Profiles profiles;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Spy
    Logger logger = LoggerFactory.getLogger(ProfileManagementImportHandler.class);

    @InjectMocks
    ProfileManagementExportHandler profileManagementExportHandler;

    @Mock
    CliUtil cliUtil;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    ProfileManagementService managementService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;


    /**
     * SetUp method for setting unittest dependency
     *
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        validCommands = new ArrayList<String>();
        validCommands.add("pfm --export --profiletype certificate");
        validCommands.add("pfm --export --profiletype certificate -n Rootcert");
        validCommands.add("pfm --export --profiletype certificate");

        invalidCommands = new ArrayList<String>();
        invalidCommands.add("pfm --export --profiletype");

        final Map<String, Object> properties = new HashMap<String, Object>();

        properties.put("command", "PROFILEMANAGEMENTEXPORT");
        properties.put("profiletype", "certificate");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.PROFILEMANAGEMENTEXPORT);
        command.setProperties(properties);
        final URL url = getClass().getClassLoader().getResource("Trustprofiles.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        Mockito.doNothing().when((exportedItemsHolder)).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getProfileManagementService()).thenReturn(managementService);
    }

    /**
     * Test Case for checking valid syntax
     */
    @Test
    public void testValidCommands() {
        for (final String command : validCommands) {
            final PkiLexer pkiLexer = new PkiLexer(new ANTLRInputStream(command));
            final PkiParser pkiParser = new PkiParser(new CommonTokenStream(pkiLexer));

            try {
                pkiParser.parseCommand();
            } catch (RecognitionException | PkiCLIException | NullPointerException e) {
                fail("command is invalid: " + command);
            }
        }
    }

    /**
     * Test Case for checking invalid syntax
     */
    @Test
    public void testInvalidCommands() {
        for (final String command : invalidCommands) {
            final PkiLexer pkiLexer = new PkiLexer(new ANTLRInputStream(command));
            final PkiParser pkiParser = new PkiParser(new CommonTokenStream(pkiLexer));

            try {
                pkiParser.parseCommand();
                fail("command is valid: " + command);
            } catch (CommandSyntaxException | RecognitionException | PkiCLIException | NullPointerException e) {
                // expected
            }
        }
    }

    /**
     * Test Case for Exporting all Certificate profiles
     */
    @Test
    public void testProcess_ProfileExportHandler_AllSuccess() {
        MockitoAnnotations.initMocks(profileManagementExportHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(managementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        Mockito.when(managementService.exportProfilesForImport(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        final PkiCommandResponse pkiCommandResponse = profileManagementExportHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    /**
     * Test Case for Exporting all Trust profiles
     */
    @Test
    public void testProcess_ProfileExportHandler_TPSuccess() {
        command.getProperties().put("profiletype", "trust");
        MockitoAnnotations.initMocks(profileManagementExportHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.TRUST_PROFILE);
        Mockito.when(managementService.exportProfiles(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        Mockito.when(managementService.exportProfilesForImport(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        final PkiCommandResponse pkiCommandResponse = profileManagementExportHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    /**
     * Test Case for Exporting all Entity profiles
     */
    @Test
    public void testProcess_ProfileExportHandler_EPSuccess() {
        command.getProperties().put("profiletype", "entity");
        MockitoAnnotations.initMocks(profileManagementExportHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.ENTITY_PROFILE);
        Mockito.when(managementService.exportProfiles(ProfileType.ENTITY_PROFILE)).thenReturn(profiles);
        Mockito.when(managementService.exportProfilesForImport(ProfileType.ENTITY_PROFILE)).thenReturn(profiles);
        final PkiCommandResponse pkiCommandResponse = profileManagementExportHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    /**
     * Test Case for Exporting all Certificate profiles
     */
    @Test
    public void testProcess_ProfileExportHandler_CPSuccess() {
        command.getProperties().put("profiletype", "certificate");
        MockitoAnnotations.initMocks(profileManagementExportHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(managementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        Mockito.when(managementService.exportProfilesForImport(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        final PkiCommandResponse pkiCommandResponse = profileManagementExportHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

    /**
     * Test Case for Exporting all Certificate profiles by name
     */
    @Test
    public void testProcess_ProfileExportHandler_CPByName() {
        command.getProperties().put("name", "cp1");
        command.getProperties().put("profiletype", "certificate");
        MockitoAnnotations.initMocks(profileManagementExportHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(0);
        certificateProfile.setName("cp1");

        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
        certificateProfiles.add(certificateProfile);
        profiles.setCertificateProfiles(certificateProfiles);
        Mockito.when(managementService.getProfile(certificateProfile)).thenReturn(certificateProfile);
        Mockito.when(managementService.getProfileForImport(certificateProfile)).thenReturn(certificateProfile);
        Mockito.when(commandHandlerUtils.getProfileInstance(ProfileType.CERTIFICATE_PROFILE)).thenCallRealMethod();
        Mockito.when(commandHandlerUtils.setProfiles(ProfileType.CERTIFICATE_PROFILE, certificateProfiles)).thenCallRealMethod();
        final PkiCommandResponse pkiCommandResponse = profileManagementExportHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

    /**
     * Test Case for checking behavior in case of Profile does not exist
     */
    @Test
    public void testProcessCommand_ProfileExportHandler_ProfileNotFound() throws IOException {

        MockitoAnnotations.initMocks(profileManagementExportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new ProfileNotFoundException()).when(managementService).exportProfiles((ProfileType) Mockito.anyObject());
        Mockito.doThrow(new ProfileNotFoundException()).when(managementService).exportProfilesForImport((ProfileType) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11106 No profile found with matching criteria"));
    }

    /**
     * Test Case for checking behavior in case of InternalServiceException
     */
    @Test
    public void testProcessCommand_ProfileExportHandler_InvalidProfileAttributeException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementExportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);

        Mockito.doThrow(new InvalidProfileAttributeException()).when(managementService).exportProfiles((ProfileType) Mockito.anyObject());
        Mockito.doThrow(new InvalidProfileAttributeException()).when(managementService).exportProfilesForImport((ProfileType) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11106 Unexpected Internal Error, please check the error log for more details."));
    }

    @Test
    public void testProcessCommand_ProfileExportHandler_ProfileServiceException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementExportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new ProfileServiceException()).when(managementService).exportProfiles((ProfileType) Mockito.anyObject());
        Mockito.doThrow(new ProfileServiceException()).when(managementService).exportProfilesForImport((ProfileType) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Suggested Solution :  retry "));

    }

    @Test
    public void testProcessCommand_ProfileExportHandler_MissingMandatoryFieldException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementExportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new MissingMandatoryFieldException()).when(managementService).exportProfiles((ProfileType) Mockito.anyObject());
        Mockito.doThrow(new MissingMandatoryFieldException()).when(managementService).exportProfilesForImport((ProfileType) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11332 Missing mandatory field:"));
    }

    /**
     * Test Case for checking behavior in case of IllegalArgumentException
     */
    @Test
    public void testProcessCommand_ProfileExportHandler_Exception() throws IOException {

        MockitoAnnotations.initMocks(profileManagementExportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new IllegalArgumentException()).when(managementService).exportProfiles((ProfileType) Mockito.anyObject());
        Mockito.doThrow(new IllegalArgumentException()).when(managementService).exportProfilesForImport((ProfileType) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Unsupported PKI command argument"));

    }

    @Test
    public void testProcessCommand_ProfileExportHandler_CommandSyntaxException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementExportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new CommandSyntaxException()).when(managementService).exportProfiles((ProfileType) Mockito.anyObject());
        Mockito.doThrow(new CommandSyntaxException()).when(managementService).exportProfilesForImport((ProfileType) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11001 Command syntax error"));
    }

    @Test
    public void testProcessCommand_ProfileExportHandler_InvalidProfileException() throws IOException {

        MockitoAnnotations.initMocks(profileManagementExportHandler);
        when(commandHandlerUtils.getProfilesFromInputXml(command)).thenReturn(profiles);
        Mockito.doThrow(new InvalidProfileException()).when(managementService).exportProfiles((ProfileType) Mockito.anyObject());
        Mockito.doThrow(new InvalidProfileException()).when(managementService).exportProfilesForImport((ProfileType) Mockito.anyObject());

        PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) profileManagementExportHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().toString().contains("Error: 11105"));

    }

    @Test
    public void test_ProfileExportHandler_SecurityViolationException() {
        MockitoAnnotations.initMocks(profileManagementExportHandler);
        Mockito.when(commandHandlerUtils.getProfileType(Mockito.anyString())).thenReturn(ProfileType.CERTIFICATE_PROFILE);
        Mockito.when(managementService.exportProfiles(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(managementService.exportProfilesForImport(ProfileType.CERTIFICATE_PROFILE)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        profileManagementExportHandler.process(command);

    }
}
