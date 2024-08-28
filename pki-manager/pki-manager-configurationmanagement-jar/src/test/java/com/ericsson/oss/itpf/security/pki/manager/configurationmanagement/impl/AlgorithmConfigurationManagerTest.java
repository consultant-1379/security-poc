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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.persistence.PersistenceException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SupportedAlgorithmsCacheOperations;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * Test class for {@link AlgorithmConfigurationManager}
 * 
 * @author xprabil
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class AlgorithmConfigurationManagerTest {

    @InjectMocks
    AlgorithmConfigurationManager algorithmConfigurationManager;

    @Mock
    private static PersistenceManager persistenceManager;

    @Mock
    private static SupportedAlgorithmsCacheOperations supportAlgorithmsCacheOperations;

    @Mock
    Logger logger;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    SystemRecorder systemRecorder;

    private static AlgorithmData supportedSignatureAlgorithm;
    private static AlgorithmData unSupportedSignatureAlgorithm;

    private static AlgorithmData supportedMessageDigestAlgorithm;
    private static AlgorithmData unSupportedMessageDigestAlgorithm;

    /**
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() {

        supportedSignatureAlgorithm = buildAlgorithmData("SHA256withRSA", AlgorithmType.SIGNATURE_ALGORITHM, "1.2.840.113549.1.1.11", true, 2048);

        supportedMessageDigestAlgorithm = buildAlgorithmData("SHA384", AlgorithmType.MESSAGE_DIGEST_ALGORITHM, "1.2.840.113549.1.1.11", true, 384);

        unSupportedSignatureAlgorithm = buildAlgorithmData("SHA1withRSA", AlgorithmType.SIGNATURE_ALGORITHM, "1.2.840.113549.1.1.5", false, 2048);

        unSupportedMessageDigestAlgorithm = buildAlgorithmData("SHA256", AlgorithmType.MESSAGE_DIGEST_ALGORITHM, "1.2.840.113549.1.1.5", false, 256);

    }

    private static AlgorithmData buildAlgorithmData(final String name, final AlgorithmType algorithmType, final String oid, final boolean supported, final Integer keySize) {
        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setName(name);
        algorithmData.setType(algorithmType.getId());
        algorithmData.setKeySize(keySize);
        algorithmData.setOid(oid);
        algorithmData.setSupported(supported);
        return algorithmData;
    }

    /**
     * @throws java.lang.Exception
     */
    @AfterClass
    public static void tearDownAfterClass() {
    }

    @Test
    public void testGetAlgorithmsByType() {

        when(persistenceManager.findEntitiesWhere(any(Class.class), anyMap())).thenReturn(
                Arrays.asList(supportedSignatureAlgorithm, unSupportedSignatureAlgorithm, supportedMessageDigestAlgorithm, unSupportedMessageDigestAlgorithm));

        final List<Algorithm> algorithms = algorithmConfigurationManager.getAlgorithmsByType(AlgorithmType.values());
        assertNotNull(algorithms);
        final Algorithm algorithmData = algorithms.get(0);
        assertEquals(supportedSignatureAlgorithm.getName(), algorithmData.getName());
        assertEquals(supportedSignatureAlgorithm.getOid(), algorithmData.getOid());
        assertEquals(AlgorithmType.SIGNATURE_ALGORITHM, algorithmData.getType());
        verify(persistenceManager).findEntitiesWhere(any(Class.class), anyMap());

    }

    @Test
    public void testGetAlgorithmsByType_Signature_Algorithms() {

        when(persistenceManager.findEntitiesWhere(any(Class.class), anyMap())).thenReturn(Arrays.asList(supportedSignatureAlgorithm, unSupportedSignatureAlgorithm));

        final List<Algorithm> algorithms = algorithmConfigurationManager.getAlgorithmsByType(AlgorithmType.values());
        assertNotNull(algorithms);
        final Algorithm algorithm = algorithms.get(0);
        assertEquals(supportedSignatureAlgorithm.getName(), algorithm.getName());
        assertEquals(supportedSignatureAlgorithm.getOid(), algorithm.getOid());
        assertEquals(AlgorithmType.SIGNATURE_ALGORITHM, algorithm.getType());
        verify(persistenceManager).findEntitiesWhere(any(Class.class), anyMap());

    }

    @Test
    public void testGetAlgorithmsByType_Exception() {

        when(persistenceManager.findEntitiesWhere(any(Class.class), anyMap())).thenThrow(new PersistenceException(""));
        try {
            algorithmConfigurationManager.getAlgorithmsByType(AlgorithmType.values());
            fail("Should throw DataAccessException");
        } catch (PKIConfigurationServiceException e) {
            // expected
        }

        verify(persistenceManager).findEntitiesWhere(any(Class.class), anyMap());

    }

    @Test
    public void testGetSupportedAlgorithmsByType() {

        when(persistenceManager.findEntitiesWhere(any(Class.class), anyMap())).thenReturn(Arrays.asList(supportedSignatureAlgorithm, supportedMessageDigestAlgorithm));

        final List<Algorithm> algorithms = algorithmConfigurationManager.getSupportedAlgorithmsByType(AlgorithmType.values());
        assertNotNull(algorithms);
        final Algorithm algorithm = algorithms.get(0);
        assertEquals(supportedSignatureAlgorithm.getName(), algorithm.getName());
        assertEquals(supportedSignatureAlgorithm.getOid(), algorithm.getOid());
        assertEquals(AlgorithmType.SIGNATURE_ALGORITHM, algorithm.getType());
        verify(persistenceManager).findEntitiesWhere(any(Class.class), anyMap());

    }

    @Test
    public void testGetSupportedAlgorithmsByType_Signature_Algorithms() {

        when(persistenceManager.findEntitiesWhere(any(Class.class), anyMap())).thenReturn(Arrays.asList(supportedSignatureAlgorithm));

        final List<Algorithm> algoriths = algorithmConfigurationManager.getSupportedAlgorithmsByType(AlgorithmType.values());
        assertNotNull(algoriths);
        final Algorithm algorithm = algoriths.get(0);
        assertEquals(supportedSignatureAlgorithm.getName(), algorithm.getName());
        assertEquals(supportedSignatureAlgorithm.getOid(), algorithm.getOid());
        assertEquals(AlgorithmType.SIGNATURE_ALGORITHM, algorithm.getType());
        verify(persistenceManager).findEntitiesWhere(any(Class.class), anyMap());

    }

    @Test
    public void testGetSupportedAlgorithmsByType_Exception() {

        when(persistenceManager.findEntitiesWhere(any(Class.class), anyMap())).thenThrow(new PersistenceException(""));
        try {
            algorithmConfigurationManager.getSupportedAlgorithmsByType(AlgorithmType.values());
            fail("Should throw DataAccessException");
        } catch (PKIConfigurationServiceException e) {
            // expected
        }

        verify(persistenceManager).findEntitiesWhere(any(Class.class), anyMap());

    }

    @Test
    public void testGetAlgorithmByNameAndKeySize() {
        final String name = "SHA256withRSA";
        final int keySize = 1024;
        Mockito.when(persistenceManager.findEntitiesByAttributes(any(Class.class), anyMap())).thenReturn(Arrays.asList(supportedSignatureAlgorithm));

        final Algorithm algorithm = algorithmConfigurationManager.getAlgorithmByNameAndKeySize(name, keySize);
        assertNotNull(algorithm);
        assertEquals(supportedSignatureAlgorithm.getName(), algorithm.getName());
        Mockito.verify(persistenceManager).findEntitiesByAttributes(any(Class.class), anyMap());

    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmByNameAndKeySize_Algorithm_Not_Found() {
        final String name = "SHA256withRSA";
        final int keySize = 1024;
        Mockito.when(persistenceManager.findEntitiesByAttributes(any(Class.class), anyMap())).thenReturn(null);
        algorithmConfigurationManager.getAlgorithmByNameAndKeySize(name, keySize);
    }

    @Test
    public void testGetAlgorithmsByName() {
        final String name = "SHA256withRSA";
        Mockito.when(persistenceManager.findEntitiesByAttributes(any(Class.class), anyMap())).thenReturn(Arrays.asList(supportedSignatureAlgorithm));

        final List<Algorithm> list = algorithmConfigurationManager.getAlgorithmsByName(name);
        assertNotNull(list);
        final Algorithm algorithm = list.get(0);
        assertEquals(supportedSignatureAlgorithm.getName(), algorithm.getName());
        Mockito.verify(persistenceManager).findEntitiesByAttributes(any(Class.class), anyMap());

    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmsByName_Algorithm_Not_Found() {
        final String name = "SHA256withRSA";
        Mockito.when(persistenceManager.findEntitiesByAttributes(any(Class.class), anyMap())).thenReturn(null);
        algorithmConfigurationManager.getAlgorithmsByName(name);
    }

    @Test
    public void testUpdateAlgorithms() {

        Mockito.when(persistenceManager.findEntitiesByAttributes(any(Class.class), anyMap())).thenReturn(Arrays.asList(supportedSignatureAlgorithm));

        final List<Algorithm> list = new ArrayList<Algorithm>();
        final Algorithm algorithm = new Algorithm();
        algorithm.setName(supportedMessageDigestAlgorithm.getName());
        algorithm.setKeySize(supportedMessageDigestAlgorithm.getKeySize());
        algorithm.setSupported(false);
        list.add(algorithm);

        Mockito.when(algorithmPersistenceHandler.getAlgorithmByNameAndKeySize(algorithm.getName(), algorithm.getKeySize())).thenReturn(supportedMessageDigestAlgorithm);
        algorithmConfigurationManager.updateAlgorithms(list);

        Mockito.verify(persistenceManager).updateEntity(supportedMessageDigestAlgorithm);

    }
}
