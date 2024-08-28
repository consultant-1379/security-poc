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

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.ConfigManagementUpdater;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

@RunWith(MockitoJUnitRunner.class)
public class ConifgManagementDisableHandlerTest {
    @Spy
    private Logger logger = LoggerFactory.getLogger(ConfigManagementDisableHandler.class);;

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @InjectMocks
    ConfigManagementDisableHandler conDisableHandler;

    @Mock
    CliUtil cliUtil;

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

        properties.put("type", "signature");
        properties.put("status", "disabled");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CONFIGMGMTDISABLE);
        command.setProperties(properties);

        algorithm.setName("TestAlgorithm");
        algorithm.setKeySize(256);

        algo.add(algorithm);

    }

    @Test
    public void testProcess_ConfigDisableHandler() {
        MockitoAnnotations.initMocks(conDisableHandler);
        final PkiMessageCommandResponse pmcr = new PkiMessageCommandResponse();
        pmcr.setMessage(Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
        when(configManagementUpdater.extractAlgorithmList((PkiPropertyCommand) Mockito.anyObject())).thenReturn(algo);
        when(configManagementUpdater.update(algo, Constants.DISABLE)).thenReturn(pmcr);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) conDisableHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testProcess_ConfigDisableHandler_SignatureAlgorithm() {
        MockitoAnnotations.initMocks(conDisableHandler);
        final PkiMessageCommandResponse pmcr = new PkiMessageCommandResponse();
        pmcr.setMessage(Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
        when(configManagementUpdater.extractAlgorithmList((PkiPropertyCommand) Mockito.anyObject())).thenReturn(algo);
        when(configManagementUpdater.update(algo, Constants.DISABLE)).thenReturn(pmcr);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) conDisableHandler.process(command);
        assertEquals(commandResponse.getMessage(), Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testProcess_ConfigDisableHandler_PKIConfigurationException() {
        MockitoAnnotations.initMocks(conDisableHandler);
        when(configManagementUpdater.extractAlgorithmList(command)).thenThrow(new PKIConfigurationException("pki configuration failed"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) conDisableHandler.process(command);
        assertEquals(commandResponse.getMessage(),
                "Error: 11007 This is an unexpected system error, please check the error log for more details. Exception occured while updating the algorithm Status pki configuration failed");
    }

    @Test
    public void testProcess_ConfigDisableHandler_NullPointerException() {
        MockitoAnnotations.initMocks(conDisableHandler);
        when(configManagementUpdater.extractAlgorithmList(command)).thenThrow(new NullPointerException("Name Can not be empty"));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) conDisableHandler.process(command);
        assertEquals(commandResponse.getMessage(),
                "Error: 11099 Unexpected Internal Error, please check the error log for more details. Exception occured while updating the algorithm Status Name Can not be empty");
    }

    @Test
    public void testProcess_ConfigDisableHandler_IllegalArgumentException() {
        MockitoAnnotations.initMocks(conDisableHandler);
        when(configManagementUpdater.extractAlgorithmList(command)).thenThrow(new IllegalArgumentException(""));
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) conDisableHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Exception occured while updating the algorithm Status"));
    }

    @Test
    public void testProcess_ConfigDisableHandler_SecurityViolationException() {
        MockitoAnnotations.initMocks(conDisableHandler);
        final PkiMessageCommandResponse pmcr = new PkiMessageCommandResponse();
        pmcr.setMessage(Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
        when(configManagementUpdater.extractAlgorithmList((PkiPropertyCommand) Mockito.anyObject())).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        conDisableHandler.process(command);
    }

}
