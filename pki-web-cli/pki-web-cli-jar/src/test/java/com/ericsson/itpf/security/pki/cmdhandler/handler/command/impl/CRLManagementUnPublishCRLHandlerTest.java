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
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.cdps.CRLPublishUnpublishStatus;

/**
 * Test Class for checking Unit test for CRLManagementUnPublishCRLHandler Class
 *
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class CRLManagementUnPublishCRLHandlerTest {
    @InjectMocks
    CRLManagementUnPublishCRLHandler crlManagementUnPublishCrlHandler;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CRLManagementUnPublishCRLHandler.class);

    @Mock
    CRLManagementService crlManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @Mock
    SystemRecorder systemRecorder;

    Map<String, Object> properties = new HashMap<String, Object>();

    PkiPropertyCommand command;

    Map<String, CRLPublishUnpublishStatus> cDPSStatus = new HashMap<String, CRLPublishUnpublishStatus>();

    @Before
    public void setUp() throws Exception {
        properties.put("command", "CRLMANAGEMENTUNPUBLISH");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CRLMANAGEMENTUNPUBLISH);
        command.setProperties(properties);
        Mockito.when(eServiceRefProxy.getCrlManagementService()).thenReturn(crlManagementService);


    }

    /**
     *
     * Test implementation for CRLManagementUnPublishCRLHandler.Processes the command to generate the CRL from service.
     *
     */

    @Test
    public void testProcess_Null() {
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementUnPublishCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11000 Entity Name cannot be null or empty.");
    }

    @Test
    public void testProcess_Success_Scenario() {
        MockitoAnnotations.initMocks(crlManagementUnPublishCrlHandler);
        properties.put("caentityname", "ENMROOTCA");

        command.setProperties(properties);
        cDPSStatus.put("ENMROOTCA", CRLPublishUnpublishStatus.SENT_FOR_UNPUBLISH);

        Mockito.when(cliUtil.splitBySeprator("ENMROOTCA", ",")).thenReturn(null);
        Mockito.when(crlManagementService.unpublishCRLFromCDPS(Mockito.anyList())).thenReturn(cDPSStatus);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn("ENMROOTCA");

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) crlManagementUnPublishCrlHandler.process(command);

        assertTrue(pkiCommandResponse.getAdditionalInformation().contains("CRL(s) unpublished successfully from CDPS by ENMROOTCA"));

    }

    @Test
    public void testProcess_Partial_Success_Scenario() {
        MockitoAnnotations.initMocks(crlManagementUnPublishCrlHandler);
        properties.put("caentityname", "ENMROOTCA,ENMSUB_CA");

        command.setProperties(properties);

        cDPSStatus.put("ENMROOTCA", CRLPublishUnpublishStatus.SENT_FOR_UNPUBLISH);
        cDPSStatus.put("ENMSUB_CA", CRLPublishUnpublishStatus.CRL_INFO_NOT_FOUND);

        Mockito.when(cliUtil.splitBySeprator("ENMROOTCA,ENMSUB_CA", ",")).thenReturn(null);
        Mockito.when(crlManagementService.unpublishCRLFromCDPS(Mockito.anyList())).thenReturn(cDPSStatus);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn("ENMROOTCA");

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) crlManagementUnPublishCrlHandler.process(command);

        assertTrue(pkiCommandResponse.getAdditionalInformation().contains("CRL(s) unpublished successfully from CDPS by ENMROOTCA."));
    }

    @Test
    public void testProcess_Failure_Scenario() {
        MockitoAnnotations.initMocks(crlManagementUnPublishCrlHandler);
        properties.put("caentityname", "ENMROOTCA,");

        command.setProperties(properties);

        cDPSStatus.put("ENMROOTCA", CRLPublishUnpublishStatus.VALID_CRL_NOT_FOUND);

        Mockito.when(cliUtil.splitBySeprator("ENMROOTCA", ",")).thenReturn(null);
        Mockito.when(crlManagementService.unpublishCRLFromCDPS(Mockito.anyList())).thenReturn(cDPSStatus);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn("ENMROOTCA");

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) crlManagementUnPublishCrlHandler.process(command);

        assertTrue(pkiCommandResponse.getAdditionalInformation().contains("CRL(s) unpublishing failed for ENMROOTCA"));
    }

    @Test
    public void testProcessCRLServiceException() {
        MockitoAnnotations.initMocks(crlManagementUnPublishCrlHandler);
        properties.put("caentityname", "ENMROOTCA,");
        command.setProperties(properties);
        cDPSStatus.put("ENMROOTCA", CRLPublishUnpublishStatus.VALID_CRL_NOT_FOUND);

        Mockito.when(cliUtil.splitBySeprator("ENMROOTCA", ",")).thenReturn(null);
        Mockito.when(crlManagementService.unpublishCRLFromCDPS(Mockito.anyList())).thenThrow(new CRLServiceException("Failed to get status"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementUnPublishCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));

    }

    @Test
    public void testProcess_SecurityViolationException() {
        MockitoAnnotations.initMocks(crlManagementUnPublishCrlHandler);
        properties.put("caentityname", "ENMROOTCA");

        command.setProperties(properties);
        cDPSStatus.put("ENMROOTCA", CRLPublishUnpublishStatus.SENT_FOR_UNPUBLISH);

        Mockito.when(cliUtil.splitBySeprator("ENMROOTCA", ",")).thenReturn(null);
        Mockito.when(crlManagementService.unpublishCRLFromCDPS(Mockito.anyList())).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        crlManagementUnPublishCrlHandler.process(command);
    }
}
