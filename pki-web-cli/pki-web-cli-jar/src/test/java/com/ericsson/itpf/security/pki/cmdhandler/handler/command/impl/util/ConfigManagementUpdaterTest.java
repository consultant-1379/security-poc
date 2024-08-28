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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

@RunWith(MockitoJUnitRunner.class)
public class ConfigManagementUpdaterTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(ConfigManagementUpdater.class);

    @Mock
    AlgorithmUtils algorithmUtils;

    @Mock
    private PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @InjectMocks
    private ConfigManagementUpdater configManagementUpdater;

    List<Algorithm> algorithms;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        algorithms = new ArrayList<Algorithm>();
        Algorithm algorithm = new Algorithm();
        algorithm.setId(1);
        algorithm.setName("RSA");
        algorithm.setKeySize(new Integer(1024));
        algorithms.add(algorithm);
        Mockito.when(eServiceRefProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService);
    }

    @Test
    public void testUpdate_ConfigUpdater() {
        PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) configManagementUpdater.update(algorithms, Constants.ENABLE);
        assertEquals(pkiCommandResponse.getMessage(), Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testUpdate_ConfigUpdater_PKIConfigurationException() {
        Mockito.when(configManagementUpdater.updateAlgorithms(algorithms, true)).thenThrow(new PKIConfigurationException(""));
        PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) configManagementUpdater.update(algorithms, Constants.ENABLE);
        assertEquals("Error: 11007 This is an unexpected system error, please check the error log for more details. ", pkiCommandResponse.getMessage());
    }

    @Test
    public void testUpdate_ConfigUpdater_Algorithms() {
        String result = configManagementUpdater.updateAlgorithms(algorithms, true);
        assertEquals(result, Constants.ALGORITHMS_UPDATED_SUCCESSFULLY);
    }

    @Test
    public void testExtract_ConfigUpdater_AlgorithmList() {
        PkiPropertyCommand command = new PkiPropertyCommand();
        command.getProperties().put(Constants.NAME, "RSA");
        command.getProperties().put(Constants.KEY_SIZE, "1024-2048");

        assertEquals("type = null, properties = {name=RSA, keysize=1024-2048}", command.toString());

        List<Integer> integers = new ArrayList<Integer>();
        integers.add(new Integer(1024));
        Mockito.when(algorithmUtils.splitBySeparator(Mockito.anyString())).thenReturn(integers);
        Mockito.when(algorithmUtils.generateAlgorithmsBasedOnKeySizeRange("RSA", integers)).thenReturn(algorithms);
        List<Algorithm> algorithms = configManagementUpdater.extractAlgorithmList(command);
        assertEquals(algorithms.get(0).getName(), "RSA");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testExtractAlgorithmList_ConfigUpdater_IllegalArgumentException() {
        PkiPropertyCommand command = new PkiPropertyCommand();

        command.getProperties().put(Constants.KEY_SIZE, "1024-2048");

        List<Integer> integers = new ArrayList<Integer>();
        List<Algorithm> algorithms = configManagementUpdater.extractAlgorithmList(command);
        assertEquals(algorithms.get(0).getName(), "RSA");
    }

    @Test
    public void testExtractAlgorithmList_ConfigUpdater() {
        PkiPropertyCommand command = new PkiPropertyCommand();

        command.getProperties().put(Constants.NAME, "RSA");

        List<Integer> integers = new ArrayList<Integer>();
        integers.add(new Integer(1024));
        Mockito.when(algorithmUtils.generateAlgorithm(Mockito.anyString())).thenReturn(algorithms.get(0));
        List<Algorithm> algorithms = configManagementUpdater.extractAlgorithmList(command);
        assertEquals(algorithms.get(0).getName(), "RSA");
    }

}
