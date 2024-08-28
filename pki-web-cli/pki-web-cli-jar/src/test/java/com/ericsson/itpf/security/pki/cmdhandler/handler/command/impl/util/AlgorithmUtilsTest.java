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


import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmUtilsTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(AlgorithmUtils.class);

    @Mock
    private PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @InjectMocks
    private AlgorithmUtils algorithmUtils;

    List<Algorithm> algorithms;
    Algorithm algorithm;
    List<Integer> keyList;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        Mockito.when(eServiceRefProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService);
        algorithm = new Algorithm();
        algorithm.setId(1);
        algorithm.setName("RSA");
        algorithm.setKeySize(1024);
        algorithm.setSupported(true);

        algorithms = new ArrayList<Algorithm>();
        algorithms.add(algorithm);

        keyList = new ArrayList<Integer>();
        keyList.add(new Integer(1024));

    }

    @Test
    public void testGetAlgorithmByName() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        Mockito.when(pkiConfigurationManagementService.getAlgorithmsByName(Mockito.anyString())).thenReturn(algorithms);
        List<Algorithm> al = algorithmUtils.getAlgorithmsByName("RSA");
        assertEquals(algorithms, al);
    }

    @Test
    public void testSplitBySeparator() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        List<Integer> integers = algorithmUtils.splitBySeparator("1024-2048");
        assertEquals(1024, integers.get(0).intValue());
    }

    @Test
    public void testGenerateAlgorithmsBasedOnMultipleKeySizes() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        List<Algorithm> al = algorithmUtils.generateAlgorithmsBasedOnMultipleKeySizes("RSA", keyList);
        assertEquals("RSA", al.get(0).getName());
    }

    @Test
    public void testGenerateAlgorithm() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        Algorithm al = algorithmUtils.generateAlgorithm("RSA", new Integer(1024));
        assertEquals("RSA", algorithms.get(0).getName());

        al = algorithmUtils.generateAlgorithm("RSA");
        assertEquals("RSA", al.getName());
    }

    @Test
    public void testGenerateAlgorithmsBasedOnKeySizeRange() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        Mockito.when(pkiConfigurationManagementService.getAlgorithmsByName(Mockito.anyString())).thenReturn(algorithms);
        keyList.add(new Integer(2048));
        List<Algorithm> al = algorithmUtils.generateAlgorithmsBasedOnKeySizeRange("RSA", keyList);
        assertEquals("RSA", al.get(0).getName());
    }

    @Test(expected = PKIConfigurationException.class)
    public void testGenerateAlgorithmsBasedOnKeySizeRangeException() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        Mockito.when(pkiConfigurationManagementService.getAlgorithmsByName(Mockito.anyString())).thenThrow(new PKIConfigurationException(""));
        algorithmUtils.generateAlgorithmsBasedOnKeySizeRange("RSA", keyList);
    }

    @Test
    public void testGetAlgorithmsByName() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        Mockito.when(pkiConfigurationManagementService.getAlgorithmsByName(Mockito.anyString())).thenReturn(algorithms);
        List<Algorithm> al = algorithmUtils.getAlgorithmsByName("RSA");
        assertEquals("RSA", al.get(0).getName());
    }

    @Test(expected = PKIConfigurationException.class)
    public void testGetAlgorithmsByNameException() {
        MockitoAnnotations.initMocks(pkiConfigurationManagementService);
        Mockito.when(pkiConfigurationManagementService.getAlgorithmsByName(Mockito.anyString())).thenThrow(new PKIConfigurationException(""));
        algorithmUtils.getAlgorithmsByName("RSA");
    }
}
