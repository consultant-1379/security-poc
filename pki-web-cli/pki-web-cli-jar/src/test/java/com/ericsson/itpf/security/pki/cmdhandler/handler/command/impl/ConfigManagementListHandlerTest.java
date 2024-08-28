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

import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;

@RunWith(MockitoJUnitRunner.class)
public class ConfigManagementListHandlerTest {

    @Spy
    private Logger logger = LoggerFactory.getLogger(ConfigManagementListHandler.class);;

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @InjectMocks
    ConfigManagementListHandler configManagementListHandler;

    @Mock
    SystemRecorder systemRecorder;

    com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand command;

    List<String> validCommands;
    List<String> invalidCommands;
    Map<String, Object> properties = new HashMap<String, Object>();
    Algorithm algorithm = new Algorithm();
    List<Algorithm> algorithms = new ArrayList<Algorithm>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("type", "signature");
        properties.put("status", "enabled");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CONFIGMGMTLIST);
        command.setProperties(properties);

        algorithm.setId(123);
        algorithm.setSupported(true);
        algorithm.setName("TestAlgorithm");

        algorithms.add(algorithm);
        Mockito.when(eServiceRefProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService);

    }

    @Test
    @Ignore
    public void testProcessForSignatureAlgorithm() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(algorithms);
        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) configManagementListHandler.process(command);
        Assert.assertEquals(2, pkiCommandResponse.size());
    }

    @Test
    public void testProcessForAllAlgorithms() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "all");
        command.setProperties(properties);
        when(
                pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM, AlgorithmType.SYMMETRIC_KEY_ALGORITHM,
                        AlgorithmType.MESSAGE_DIGEST_ALGORITHM)).thenReturn(algorithms);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) configManagementListHandler.process(command);
        Assert.assertTrue(pkiCommandResponse.getMessage().contains("Error: 11006 Algorithm not found with the given status"));
    }

    @Test
    public void testProcessForDigestAlgorithms() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "digest");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM)).thenReturn(algorithms);
        final PkiCommandResponse pkiCommandResponse = configManagementListHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.NAME_MULTIPLE_VALUE);
    }

    @Test
    public void testProcessForDigestAlgorithmsReturnNULLd() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "digest");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM)).thenReturn(null);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) configManagementListHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11006 Algorithm not found with the given status"));
    }

    @Test
    public void testProcessForAsymmetricKeyGenAlgorithms() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "asymmetric");
        properties.put("status", "all");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(algorithms);
        configManagementListHandler.process(command);
    }

    @Test
    public void testProcessForSymmetricKeyGenAlgorithms() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "symmetric");
        properties.put("status", "all");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenReturn(algorithms);
        configManagementListHandler.process(command);
    }

    @Test
    public void testProcessForInvalidAlgorithms() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "sig");
        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) configManagementListHandler.process(command);

        Assert.assertTrue(pkiCommandResponse.getMessage().contains("Error: 11102 This is an unexpected system error,"));

    }

    @Test
    public void testProcessForAsymmetricKeyGenAlgorithmsEx() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "asymmetric");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenThrow(new PKIConfigurationException("PKI configuration failed"));
        configManagementListHandler.process(command);
    }

    @Test
    public void testProcessForSymmetricKeyGenAlgorithmsEx() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "symmetric");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenThrow(new PKIConfigurationException("PKI configuration failed"));
        configManagementListHandler.process(command);
    }

    @Test
    public void testProcessForAlgorithmNotFoundException() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        properties.put("type", "symmetric");
        command.setProperties(properties);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.SYMMETRIC_KEY_ALGORITHM)).thenThrow(new AlgorithmNotFoundException("PKI configuration failed"));
        configManagementListHandler.process(command);
    }

    @Test
    public void testProcessForSignatureAlgorithm_SecurityViolationException() {
        MockitoAnnotations.initMocks(configManagementListHandler);
        when(pkiConfigurationManagementService.getAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        configManagementListHandler.process(command);

    }
}
