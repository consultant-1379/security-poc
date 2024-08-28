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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.util.exception.IllegalAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

@RunWith(MockitoJUnitRunner.class)
public class RevocationManagementRevokeEntityCertHandlerTest {

    @InjectMocks
    private RevocationManagementRevokeEntityCertHandler revocationManagementRevokeEntityCertHandler;

    @Mock
    private CommandHandlerUtils commandHandlerUtils;

    @Mock
    private CliUtil cliUtil;

    @Mock
    private RevocationService revocationService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    private final Logger logger = LoggerFactory.getLogger(RevocationManagementRevokeEntityCertHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    private PkiPropertyCommand command;

    private String invaliditydate = "2015-11-11 10:15:11";

    private Map<String, Object> properties;

    private final String commandKey = "command";
    private final String reasonTextKey = "reasontext";
    private final String entityNameKey = "entityname";
    private final String invalidityDateKey = "invaliditydate";
    private final String subjectDNKey = "subjectDN";
    private final String serialNoKey = "serialno";
    private final String issuerDNKey = "issuerDN";
    private final String reasonCodeKey = "reasoncode";
    private final String issuerNameKey = "issuername";

    private final String commandValue = "REVOCATIONMANAGEMENTREVOKEENTITYCERT";
    private String reasonTextValue = "keyCompromise";
    private String entityNameValue = "ERBS123";
    private String invalidityDateValue = "2015-11-11 10:15:11";

    private String issuerNameValue = "CAENM";
    private String serialNoValue = "lgyus";

    private String subjectDNValue = "CN=Test, O=TCS";
    private String issuerDNValue = "CN=Test, O=TCS";
    private String reasonCodeValue = "1";

    @Before
    public void setUp() {

        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.REVOCATIONMANAGEMENTREVOKEENTITYCERT);

        MockitoAnnotations.initMocks(revocationManagementRevokeEntityCertHandler);
        Mockito.when(eServiceRefProxy.getRevocationService()).thenReturn(revocationService);

    }

    @Test
    public void testProcessCommand() {

        String expectedMsg = "Certificate with name:: ERBS123 revoked successfully";
        properties = getEntityNameProperties();
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);
        Mockito.verify(commandHandlerUtils).getInvalidityDateInGmt(invaliditydate);

        assertEquals(pkiCommandResponse.getMessage(), expectedMsg);
    }

    @Test
    public void testProcessCommand_Throws_CertificateNotFoundException() {

        String expectedMsg = "No valid Certificate found";
        properties = getEntityNameProperties();
        command.setProperties(properties);

        Mockito.doThrow(new CertificateNotFoundException(expectedMsg)).when(revocationService)
                .revokeEntityCertificates(Mockito.anyString(), (RevocationReason) Mockito.anyObject(), (Date) Mockito.anyObject());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);
        Mockito.verify(commandHandlerUtils).getInvalidityDateInGmt(invaliditydate);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessCommandCAIdentifier() {

        String expectedMsg = "Certificate with serial number:: lgyus revoked successfully";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);

        assertEquals(pkiCommandResponse.getMessage(), expectedMsg);
    }

    @Test
    public void testProcessCommandDN() {

        String expectedMsg = "Certificate with Subject DN:: CN=Test, O=TCS revoked successfully";
        properties = getSubjectDnProperties();
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);
        assertEquals(pkiCommandResponse.getMessage(), expectedMsg);
    }

    @Test
    public void testProcessCommandEntityNameNull() {

        String expectedMsg = "11000 Entity Name cannot be null or empty";
        properties = getEntityNameProperties();
        properties.put(entityNameKey, null);
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);
        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessCommandCAIdentifierIssuerNameNull() {

        String expectedMsg = "11000 Issuer Name cannot be null or empty";
        properties = getIssuerNameProperties();
        properties.put(issuerNameKey, null);
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);
        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessCommandIssuerDNNull() {

        String expectedMsg = "11000 Issuer DN cannot be null or empty.";
        properties = getSubjectDnProperties();
        properties.put(issuerDNKey, "");
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);
        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));

    }

    @Test
    public void testProcessCommandCAIdentifierSerailNumberNull() {

        String expectedMsg = "11000 Certificate Serial Number cannot be null or empty.";
        properties = getIssuerNameProperties();
        properties.put(serialNoKey, null);
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        Mockito.verify(commandHandlerUtils).getRevocationReason(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessCertificateNotFoundException() {

        String expectedMsg = "Certificate revocation failed.The issuer name or Certificate Serial Number is incorrect. Please check the logs for more information.";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new CertificateNotFoundException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessEntityNotFoundException() {

        String expectedMsg = "Certificate revocation failed.Entity name may be incorrect. Please check the logs for more information.";
        properties = getEntityNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new EntityNotFoundException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessExpiredCertificateException() {

        String expectedMsg = "Error: 11603";
        properties = getEntityNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new ExpiredCertificateException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessIssuerNotFoundException() {

        String expectedMsg = "Issuer is not found, Please refer to an existing issuer";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new IssuerNotFoundException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessRevokedCertificateException() {

        String expectedMsg = "Error: 11604";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new RevokedCertificateException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessRevocationServiceException() {

        String expectedMsg = " retry ";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new RevocationServiceException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessCommandInvalidityDateWrongFormat() {

        String expectedMsg = "Error: 11099 Unexpected Internal Error, ";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new IllegalAttributeException("Date format Not supported "));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));

    }

    @Test
    public void testProcessCommandRevocationReasonInvalidCode() {

        String expectedMsg = "11601 Revocation Reason not supported, please check user guide or online help for the list of supported revocation reasons";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new IllegalArgumentException("Reason not supported"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessCommandRevocationReasonInvalidText() {

        String expectedMsg = "11601 Revocation Reason not supported, please check user guide or online help for the list of supported revocation reasons";
        properties = getIssuerNameProperties();
        command.setProperties(properties);

        Mockito.when(revocationManagementRevokeEntityCertHandler.process(command)).thenThrow(new IllegalArgumentException("Reason not supported"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) revocationManagementRevokeEntityCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(expectedMsg));
    }

    @Test
    public void testProcessCommand_SecurityViolationException() {

        properties = getEntityNameProperties();
        command.setProperties(properties);

        Mockito.when(commandHandlerUtils.getRevocationReason(command)).thenReturn(RevocationReason.KEY_COMPROMISE);
        Mockito.when(commandHandlerUtils.getInvalidityDateInGmt(command.getValueString(Constants.INVALIDITY_DATE))).thenReturn(null);
        Mockito.doThrow(SecurityViolationException.class).when(revocationService).revokeEntityCertificates("ENMServiceCA", RevocationReason.KEY_COMPROMISE, null);
        revocationManagementRevokeEntityCertHandler.process(command);

    }

    private Map<String, Object> getEntityNameProperties() {

        Map<String, Object> entityNameProperties = new HashMap<String, Object>();

        entityNameProperties.put(commandKey, commandValue);
        entityNameProperties.put(reasonTextKey, reasonTextValue);
        entityNameProperties.put(entityNameKey, entityNameValue);
        entityNameProperties.put(invalidityDateKey, invalidityDateValue);

        return entityNameProperties;

    }

    private Map<String, Object> getIssuerNameProperties() {

        Map<String, Object> issuerNameProperties = new HashMap<String, Object>();

        issuerNameProperties.put(commandKey, commandValue);
        issuerNameProperties.put(reasonTextKey, reasonTextValue);
        issuerNameProperties.put(issuerNameKey, issuerNameValue);
        issuerNameProperties.put(serialNoKey, serialNoValue);

        return issuerNameProperties;

    }

    private Map<String, Object> getSubjectDnProperties() {

        Map<String, Object> subjectDnProperties = new HashMap<String, Object>();

        subjectDnProperties.put(subjectDNKey, subjectDNValue);
        subjectDnProperties.put(serialNoKey, serialNoValue);
        subjectDnProperties.put(issuerDNKey, issuerDNValue);
        subjectDnProperties.put(reasonCodeKey, reasonCodeValue);

        return subjectDnProperties;

    }

}
