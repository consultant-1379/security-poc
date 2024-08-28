/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import static org.mockito.Mockito.times;

import java.util.*;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmPersistenceHandlerTest {

    @InjectMocks
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    private static final String name = "ABC";
    private final Integer keySize = new Integer(256);

    private static final String ALGORITHM_NAME = "name";
    private static final String ALGORITHM_TYPE = "type";
    private static final String ALGORITHM_KEYSIZE = "keySize";
    private static final String ALGORITHM_SUPPORTED = "supported";
    private static final String ALGORITHM_CATEGORIES = "categories";

    @Test(expected = CoreEntityServiceException.class)
    public void testGetAlgorithmByNameAndKeySize() {
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("name", name);
        parameters.put("keySize", keySize);
        final List<AlgorithmData> list = new ArrayList<AlgorithmData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);

        algorithmPersistenceHandler.getAlgorithmByNameAndKeySize(name, keySize);

        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(AlgorithmData.class, parameters);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testGetAlgorithmByNameAndKeySize_PersistenceException() {
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("name", name);
        parameters.put("keySize", keySize);
        final List<AlgorithmData> list = new ArrayList<AlgorithmData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenThrow(new PersistenceException());

        algorithmPersistenceHandler.getAlgorithmByNameAndKeySize(name, keySize);

        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(AlgorithmData.class, parameters);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testGetAlgorithmsByName() {
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        final List<AlgorithmData> list = new ArrayList<AlgorithmData>();
        parameters.put("name", name);

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);

        algorithmPersistenceHandler.getAlgorithmsByName("ABC");

        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(AlgorithmData.class, parameters);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testGetAlgorithmsByName_PersistenceException() {
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        final List<AlgorithmData> list = new ArrayList<AlgorithmData>();
        parameters.put("name", name);

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);
        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenThrow(new PersistenceException());
        algorithmPersistenceHandler.getAlgorithmsByName("ABC");

        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(AlgorithmData.class, parameters);
    }

    @Test(expected = Exception.class)
    public void testGetAlgorithmByNameAndType() {
        final Algorithm algorithm = getAlgorithm(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        final List<AlgorithmData> list = new ArrayList<AlgorithmData>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());
        parameters.put(ALGORITHM_NAME, algorithm.getName());
        parameters.put(ALGORITHM_CATEGORIES, categories);

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);

        algorithmPersistenceHandler.getAlgorithmByNameAndType(algorithm, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        Mockito.verify(persistenceManager).findEntitiesByAttributes(AlgorithmData.class, parameters);
    }

    @Test(expected = Exception.class)
    public void testGetAlgorithmByNameAndType_PersistenceException() {
        final Algorithm algorithm = getAlgorithm(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        final List<AlgorithmData> list = new ArrayList<AlgorithmData>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());
        parameters.put(ALGORITHM_NAME, algorithm.getName());
        parameters.put(ALGORITHM_CATEGORIES, categories);

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);
        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenThrow(new PersistenceException());
        algorithmPersistenceHandler.getAlgorithmByNameAndType(algorithm, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        Mockito.verify(persistenceManager).findEntitiesByAttributes(AlgorithmData.class, parameters);
    }

    @Test(expected = Exception.class)
    public void testGetAlgorithmByNameAndType_AlgorithmType_SIGNATURE_ALGORITHM_PersistenceException() {
        final Algorithm algorithm = getAlgorithm(AlgorithmType.SIGNATURE_ALGORITHM);
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        final List<AlgorithmData> list = new ArrayList<AlgorithmData>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());
        parameters.put(ALGORITHM_NAME, algorithm.getName());
        parameters.put(ALGORITHM_CATEGORIES, categories);

        //Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);
        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenThrow(new PersistenceException());
        algorithmPersistenceHandler.getAlgorithmByNameAndType(algorithm, AlgorithmType.SIGNATURE_ALGORITHM);

        Mockito.verify(persistenceManager).findEntitiesByAttributes(AlgorithmData.class, parameters);
    }

    /**
     * @return
     */
    private Algorithm getAlgorithm(AlgorithmType type) {
        final Algorithm algorithm = new Algorithm();
        algorithm.setId(123);
        algorithm.setName("ABCDEF");
        algorithm.setType(type);
        return algorithm;
    }

}
