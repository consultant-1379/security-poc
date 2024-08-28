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

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCACRLsExistException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementDeleteExtCAHandlerTest {

    @InjectMocks
    EntityManagementDeleteExtCAHandler entityManagementDeleteExtCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    private ExtCACertificateManagementService extCaCertificateManagementService;

    @Mock
    private ExtCACRLManagementService extCaCrlManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementImportExtCAHandler.class);

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        properties.put("command", "EXTERNALCAREMOVE");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.EXTERNALCAREMOVE);
        properties.put("name", "caName");
        command.setProperties(properties);
        Mockito.when(eServiceRefProxy.getExtCaCertificateManagementService()).thenReturn(extCaCertificateManagementService);
        Mockito.when(eServiceRefProxy.getExtCaCrlManagementService()).thenReturn(extCaCrlManagementService);
    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementListCAHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommandRemoveExtCA() {
        Mockito.doNothing().when(extCaCertificateManagementService).remove("caName");

        final PkiCommandResponse pkiCommandResponse = entityManagementDeleteExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandRemoveExtCAException1() {
        Mockito.doThrow(new ExternalCANotFoundException("Error")).when(extCaCertificateManagementService).remove("caName");

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementDeleteExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_ARGUMENT));
    }

    @Test
    public void testProcessCommandRemoveExtCAException2() {
        Mockito.doThrow(new ExternalCAInUseException("Error")).when(extCaCertificateManagementService).remove("caName");

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementDeleteExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_ARGUMENT));
    }

    @Test
    public void testProcessCommandRemoveExtCAException3() {
        Mockito.doThrow(new CommonRuntimeException("Error")).when(extCaCertificateManagementService).remove("caName");

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementDeleteExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.RUNTIME_EXCEPTION));
    }

    @Test
    public void testProcessCommandRemoveExtCAException4() {
        Mockito.doThrow(new ExternalCredentialMgmtServiceException("Error")).when(extCaCertificateManagementService).remove("caName");

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementDeleteExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11002 Error while deleting entity"));
    }

    @Test
    public void testProcessCommandRemoveExtCAException5() {
        Mockito.doThrow(new ExternalCANotFoundException("Error")).when(extCaCertificateManagementService).remove("caName");

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementDeleteExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_ARGUMENT));
    }

    @Test
    public void testProcessCommandRemoveExtCA_MissingMandatoryFieldException() {
        Mockito.doThrow(new MissingMandatoryFieldException("Error")).when(extCaCertificateManagementService).remove("caName");

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementDeleteExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11332 Missing mandatory field:"));

    }

    @Test
    public void testProcessCommandRemoveExtCA_ExternalCACRLsExistException() {
        Mockito.doThrow(new ExternalCACRLsExistException("Error")).when(extCaCertificateManagementService).remove("caName");

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) entityManagementDeleteExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error while deleting entity "));
    }

    @Test
    public void testProcessCommandRemoveExtCA_SecurityViolationException() {
        Mockito.doNothing().when(extCaCertificateManagementService).remove("caName");
        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(extCaCertificateManagementService).remove("caName");
        entityManagementDeleteExtCaHandler.process(command);

    }

}
