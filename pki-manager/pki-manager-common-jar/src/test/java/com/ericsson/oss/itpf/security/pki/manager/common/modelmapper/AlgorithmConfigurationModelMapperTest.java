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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.junit.*;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * Test class for {@link AlgorithmConfigurationModelMapper}
 * 
 * @author xprabil
 * 
 */
public class AlgorithmConfigurationModelMapperTest {

    private static AlgorithmData supportedSignatureAlgorithmData;
    private static Algorithm algorithm;

    @Inject
    private static AlgorithmConfigurationModelMapper mapper;

    /**
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() {

        algorithm = new Algorithm();
        algorithm.setName("SHA256withRSA");
        algorithm.setOid("1.2.840.113549.1.1.11");
        algorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        algorithm.setKeySize(2048);

        supportedSignatureAlgorithmData = buildAlgorithmData("SHA256withRSA", AlgorithmType.SIGNATURE_ALGORITHM, "1.2.840.113549.1.1.11", true, 2048);

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

        mapper = null;
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper#toAlgorithmData(java.util.List)} .
     */
    @Test
    public void testToAlgorithmDataListOfAlgorithm() {

        final List<Algorithm> algorithms = new ArrayList<Algorithm>();
        algorithms.add(algorithm);

        final AlgorithmData[] algorithmDatas = mapper.toAlgorithmData(algorithms);

        final AlgorithmData algorithmData = algorithmDatas[0];

        assertEquals(algorithmData.getName(), algorithm.getName());
        assertEquals(algorithmData.getOid(), algorithm.getOid());
        assertEquals(AlgorithmType.getType(algorithmData.getType()).name(), algorithm.getType().name());
        assertEquals(algorithmData.getKeySize(), algorithm.getKeySize());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper#fromAlgorithmData(java.util.List)} .
     */
    @Test
    public void testToAlgorithmListOfAlgorithmData() {

        final List<AlgorithmData> algorithmDatas = new ArrayList<AlgorithmData>();
        algorithmDatas.add(supportedSignatureAlgorithmData);

        final List<Algorithm> algorithms = mapper.fromAlgorithmData(algorithmDatas);

        final Algorithm algorithm = algorithms.get(0);

        assertEquals(algorithm.getName(), supportedSignatureAlgorithmData.getName());
        assertEquals(algorithm.getOid(), supportedSignatureAlgorithmData.getOid());
        assertEquals(algorithm.getType().name(), AlgorithmType.getType(supportedSignatureAlgorithmData.getType()).name());
        assertEquals(algorithm.getKeySize(), supportedSignatureAlgorithmData.getKeySize());
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper#toAlgorithmData(com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.model.Algorithm)}
     * .
     */
    @Test
    public void testToAlgorithmDataAlgorithm() {

        final AlgorithmData algorithmData = mapper.toAlgorithmData(algorithm);

        assertEquals(algorithmData.getName(), algorithm.getName());
        assertEquals(algorithmData.getOid(), algorithm.getOid());
        assertEquals(AlgorithmType.getType(algorithmData.getType()).name(), algorithm.getType().name());
        assertEquals(algorithmData.getKeySize(), algorithm.getKeySize());
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper#fromAlgorithmData(com.ericsson.oss.itpf.security.pki.manager.persistence.entities.configurationmanagement.persistence.entity.AlgorithmData)}
     * .
     */
    @Test
    public void testToAlgorithmAlgorithmData() {

        final Algorithm algorithm = mapper.fromAlgorithmData(supportedSignatureAlgorithmData);

        assertEquals(algorithm.getName(), supportedSignatureAlgorithmData.getName());
        assertEquals(algorithm.getOid(), supportedSignatureAlgorithmData.getOid());
        assertEquals(algorithm.getType().name(), AlgorithmType.getType(supportedSignatureAlgorithmData.getType()).name());
        assertEquals(algorithm.getKeySize(), supportedSignatureAlgorithmData.getKeySize());
    }

}
