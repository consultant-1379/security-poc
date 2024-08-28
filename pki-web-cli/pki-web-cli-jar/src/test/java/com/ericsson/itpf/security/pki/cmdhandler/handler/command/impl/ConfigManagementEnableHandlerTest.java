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
import static org.mockito.Mockito.when;

import java.util.*;

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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.*;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

@RunWith(MockitoJUnitRunner.class)
public class ConfigManagementEnableHandlerTest {

    @Spy
    private Logger logger = LoggerFactory.getLogger(ConfigManagementEnableHandler.class);;

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @InjectMocks
    ConfigManagementEnableHandler configEnableHandler;

    @Mock
    CliUtil cliUtil;

    @Mock
    AlgorithmUtils algorithmUtils;

    @Mock
    ConfigManagementUpdater configManagementUpdater;

    @Mock
    SystemRecorder systemRecorder;

    Map<String, Object> properties = new HashMap<String, Object>();
    PkiCommandResponse pkiCommandResponse;
    PkiPropertyCommand command;
    Algorithm algorithm = new Algorithm();
    List<Algorithm> algo = new ArrayList<Algorithm>();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("name", "RSA");
        properties.put("keysize", "1024");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CONFIGMGMTENABLE);
        command.setProperties(properties);

        algorithm.setName("TestAlgorithm");
        algorithm.setKeySize(256);

        algo.add(algorithm);

    }

    @Test
    public void testProcess_ConfigEnableHandler() {
        MockitoAnnotations.initMocks(configEnableHandler);
        final PkiMessageCommandResponse pkiMessageCommandResponse = new PkiMessageCommandResponse();
        pkiMessageCommandResponse.setMessage(Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
        when(configManagementUpdater.extractAlgorithmList((PkiPropertyCommand) Mockito.anyObject())).thenReturn(algo);
        when(configManagementUpdater.update(algo, Constants.ENABLE)).thenReturn(pkiMessageCommandResponse);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configEnableHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testProcess_ConfigEnableHandler_SignatureAlgorithm() {
        MockitoAnnotations.initMocks(configEnableHandler);
        final PkiMessageCommandResponse pkiMessageCommandResponse = new PkiMessageCommandResponse();
        pkiMessageCommandResponse.setMessage(Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
        when(configManagementUpdater.extractAlgorithmList((PkiPropertyCommand) Mockito.anyObject())).thenReturn(algo);
        when(configManagementUpdater.update(algo, Constants.ENABLE)).thenReturn(pkiMessageCommandResponse);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configEnableHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testProcess_ConfigEnableHandler_PKIConfigurationException() {
        MockitoAnnotations.initMocks(configEnableHandler);
        when(configManagementUpdater.extractAlgorithmList(command)).thenThrow(new PKIConfigurationException("pki configuration failed"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configEnableHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11007 This is an unexpected system error, please check the error log for more details. pki configuration failed");
    }

    @Test
    public void testProcess_ConfigEnableHandler_NullPointerException() {
        MockitoAnnotations.initMocks(configEnableHandler);
        when(configManagementUpdater.extractAlgorithmList(command)).thenThrow(new NullPointerException("Algorithm can not be empty"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configEnableHandler.process(command);
        assertEquals(commandResponse.getMessage(), "Error: 11099 Unexpected Internal Error, please check the error log for more details.Algorithm can not be empty");
    }

    @Test
    public void testProcess_ConfigEnableHandler_IllegalArgumentException() {
        MockitoAnnotations.initMocks(configEnableHandler);
        when(configManagementUpdater.extractAlgorithmList(command)).thenThrow(new IllegalArgumentException("not valid argument"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) configEnableHandler.process(command);
        assertEquals(commandResponse.getMessage(),
                "Error: 11102 This is an unexpected system error, please check the error log for more details. Exception occured while updating the algorithm Status not valid argument");
    }

    @Test
    public void test_ConfigEnableHandler_SignatureAlgorithm_SecurityViolationException() {
        MockitoAnnotations.initMocks(configEnableHandler);
        final PkiMessageCommandResponse pkiMessageCommandResponse = new PkiMessageCommandResponse();
        pkiMessageCommandResponse.setMessage(Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
        when(configManagementUpdater.extractAlgorithmList((PkiPropertyCommand) Mockito.anyObject())).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        //        when(configManagementUpdater.update(algo, Constants.ENABLE)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        configEnableHandler.process(command);
    }

    @Test
    public void test_ConfigEnableHandler_SignatureAlgorithm_SecurityViolationException1() {
        MockitoAnnotations.initMocks(configEnableHandler);
        final PkiMessageCommandResponse pkiMessageCommandResponse = new PkiMessageCommandResponse();
        pkiMessageCommandResponse.setMessage(Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
        when(configManagementUpdater.update(algo, Constants.ENABLE)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        configEnableHandler.process(command);
    }
}
