/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmPersistenceHandlerTest {

    @InjectMocks
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    private Algorithm algorithm;
    private AlgorithmData algoData;
    HashMap<String, Object> parameters;

    @Before
    public void setUp() {

        algorithm = new Algorithm();
        algoData = new AlgorithmData();

        parameters = new HashMap<String, Object>();
    }

    @Test
    public void testGetAlgorithmByNameAndKeySize() {

        List<AlgorithmData> list = new ArrayList<AlgorithmData>();
        list.add(algoData);

        parameters.put("name", "name");
        parameters.put("keySize", 2);

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);

        assertNotNull(algorithmPersistenceHandler.getAlgorithmByNameAndKeySize("name", 2));
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testgetAlgorithmByNameAndKeySizeAlgorithmNotFoundException() {

        HashMap<String, Object> parameters = new HashMap<String, Object>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(null);

        assertNotNull(algorithmPersistenceHandler.getAlgorithmByNameAndKeySize("name", 2));
    }

    @Test
    public void testGetAlgorithmsByName() {

        List<AlgorithmData> list = new ArrayList<AlgorithmData>();
        list.add(algoData);

        parameters.put("name", "name");

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(list);

        assertNotNull(algorithmPersistenceHandler.getAlgorithmsByName("name"));
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmsByNameAlgorithmNotFoundException() {

        parameters.put("name", "name");

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, parameters)).thenReturn(null);

        algorithmPersistenceHandler.getAlgorithmsByName("name");
    }

    @Test
    public void testGetAlgorithmByNameAndType() {
        final Map<String, Object> input = new HashMap<String, Object>();

        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());

        input.put("name", algorithm.getName());
        input.put("categories", categories);
        input.put("type", AlgorithmType.SIGNATURE_ALGORITHM.getId());
        input.put("supported", Boolean.TRUE);

        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(algoData);
        assertEquals(algoData, algorithmPersistenceHandler.getAlgorithmByNameAndType(algorithm, AlgorithmType.SIGNATURE_ALGORITHM));
    }

    @Test
    public void testGetAlgorithmByNameAndTypeWithOutSignatureAlgorithm() {
        final Map<String, Object> input = new HashMap<String, Object>();

        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());

        input.put("name", algorithm.getName());
        input.put("categories", categories);
        final AlgorithmType type = algorithm.getType() == null ? AlgorithmType.ASYMMETRIC_KEY_ALGORITHM : algorithm.getType();
        input.put("type", type.getId());
        input.put("supported", Boolean.TRUE);
        input.put("keySize", algorithm.getKeySize());

        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(algoData);
        assertEquals(algoData, algorithmPersistenceHandler.getAlgorithmByNameAndType(algorithm, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM));
    }
}
