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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.service;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ConfigurationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl.AlgorithmConfigurationManager;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl.EntityCategoryConfigurationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * Test class for {@link PKIConfigurationManagementServiceBean}
 *
 * @author xprabil
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class PKIConfigurationManagementServiceBeanTest {

    @Mock
    private static AlgorithmConfigurationManager algorithmConfigurationManager;

    @Mock
    ConfigurationManagementAuthorizationManager configurationManagementAuthorizationManager;

    @Mock
    EntityCategoryConfigurationManager entityCategoryConfigurationManager;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @InjectMocks
    PKIConfigurationManagementServiceBean pKIConfigurationService;

    private static AlgorithmData supportedSignatureAlgorithm;

    private static AlgorithmData supportedMessageDigestAlgorithm;

    private static Algorithm supportedSignatureAlg;
    private static Algorithm unSupportedSignatureAlg;

    private static Algorithm supportedMessageDigestAlg;
    private static Algorithm unSupportedMessageDigestAlg;

    private static Algorithm algorithm;

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

        supportedSignatureAlgorithm = buildAlgorithmData("SHA256withRSA", AlgorithmType.SIGNATURE_ALGORITHM, "1.2.840.113549.1.1.11", true, 2048);

        supportedMessageDigestAlgorithm = buildAlgorithmData("SHA384", AlgorithmType.MESSAGE_DIGEST_ALGORITHM, "1.2.840.113549.1.1.11", true, 384);

        supportedSignatureAlg = buildAlgorithm("SHA256withRSA", AlgorithmType.SIGNATURE_ALGORITHM, "1.2.840.113549.1.1.11", true, 2048);

        supportedMessageDigestAlg = buildAlgorithm("SHA384", AlgorithmType.MESSAGE_DIGEST_ALGORITHM, "1.2.840.113549.1.1.11", true, 384);

        unSupportedSignatureAlg = buildAlgorithm("SHA1withRSA", AlgorithmType.SIGNATURE_ALGORITHM, "1.2.840.113549.1.1.5", false, 2048);

        unSupportedMessageDigestAlg = buildAlgorithm("SHA256", AlgorithmType.MESSAGE_DIGEST_ALGORITHM, "1.2.840.113549.1.1.5", false, 256);

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

    private static Algorithm buildAlgorithm(final String name, final AlgorithmType algorithmType, final String oid, final boolean supported, final Integer keySize) {
        final Algorithm algorithm = new Algorithm();
        algorithm.setName(name);
        algorithm.setType(algorithmType);
        algorithm.setKeySize(keySize);
        algorithm.setOid(oid);
        algorithm.setSupported(supported);
        return algorithm;
    }

    /**
     * @throws java.lang.Exception
     */
    @AfterClass
    public static void tearDownAfterClass() {
    }

    @Test
    public void testGetAlgorithmsByType() {

        Mockito.when(algorithmConfigurationManager.getAlgorithmsByType(AlgorithmType.values())).thenReturn(
                Arrays.asList(supportedSignatureAlg, unSupportedSignatureAlg, supportedMessageDigestAlg, unSupportedMessageDigestAlg));

        final List<Algorithm> algorithms = pKIConfigurationService.getAlgorithmsByType(AlgorithmType.values());
        assertNotNull(algorithms);
        assertEquals(4, algorithms.size());
        final Algorithm algorithm = algorithms.get(0);
        assertEquals(supportedSignatureAlg.getName(), algorithm.getName());
        assertEquals(supportedSignatureAlg.getOid(), algorithm.getOid());
        assertEquals(supportedSignatureAlg.getKeySize(), algorithm.getKeySize());
        assertEquals(AlgorithmType.SIGNATURE_ALGORITHM, algorithm.getType());
        Mockito.verify(algorithmConfigurationManager).getAlgorithmsByType(AlgorithmType.values());
    }

    @Test
    public void testGetAlgorithmsByType_Signatures() {
        Mockito.when(algorithmConfigurationManager.getAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(Arrays.asList(supportedSignatureAlg, unSupportedSignatureAlg));
        final List<Algorithm> algorithms = pKIConfigurationService.getAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM);
        assertNotNull(algorithms);
        final Algorithm algorithm = algorithms.get(0);
        assertEquals(supportedSignatureAlg.getName(), algorithm.getName());
        assertEquals(supportedSignatureAlg.getOid(), algorithm.getOid());
        assertEquals(supportedSignatureAlg.getKeySize(), algorithm.getKeySize());
        assertEquals(AlgorithmType.SIGNATURE_ALGORITHM, algorithm.getType());
        Mockito.verify(algorithmConfigurationManager).getAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM);
    }

    @Test
    public void testGetAlgorithmsByType_MessageDigests() {
        Mockito.when(algorithmConfigurationManager.getAlgorithmsByType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM)).thenReturn(Arrays.asList(supportedMessageDigestAlg, unSupportedMessageDigestAlg));
        final List<Algorithm> algorithms = pKIConfigurationService.getAlgorithmsByType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
        assertNotNull(algorithms);
        final Algorithm algorithm = algorithms.get(0);
        assertEquals(supportedMessageDigestAlg.getName(), algorithm.getName());
        assertEquals(supportedMessageDigestAlg.getOid(), algorithm.getOid());
        assertEquals(supportedMessageDigestAlg.getKeySize(), algorithm.getKeySize());
        assertEquals(AlgorithmType.MESSAGE_DIGEST_ALGORITHM, algorithm.getType());
        Mockito.verify(algorithmConfigurationManager).getAlgorithmsByType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmsByType_Exception() {
        Mockito.when(algorithmConfigurationManager.getAlgorithmsByType(AlgorithmType.values())).thenThrow(new AlgorithmNotFoundException());

        pKIConfigurationService.getAlgorithmsByType(AlgorithmType.values());

    }

    @Test
    public void testGetSupportedAlgorithmsByType() {
        Mockito.when(algorithmConfigurationManager.getSupportedAlgorithmsByType(AlgorithmType.values())).thenReturn(Arrays.asList(supportedSignatureAlg, supportedMessageDigestAlg));
        final List<Algorithm> algorithms = pKIConfigurationService.getSupportedAlgorithmsByType(AlgorithmType.values());
        assertNotNull(algorithms);
        final Algorithm algorithm = algorithms.get(0);
        assertEquals(supportedSignatureAlg.getName(), algorithm.getName());
        assertEquals(supportedSignatureAlg.getOid(), algorithm.getOid());
        assertEquals(supportedSignatureAlg.getKeySize(), algorithm.getKeySize());
        assertEquals(AlgorithmType.SIGNATURE_ALGORITHM, algorithm.getType());
        Mockito.verify(algorithmConfigurationManager).getSupportedAlgorithmsByType(AlgorithmType.values());
    }

    @Test(expected = PKIConfigurationServiceException.class)
    public void testGetSupportedAlgorithmsByType_Exception() {
        Mockito.when(algorithmConfigurationManager.getSupportedAlgorithmsByType(AlgorithmType.values())).thenThrow(new PKIConfigurationServiceException());

        pKIConfigurationService.getSupportedAlgorithmsByType(AlgorithmType.values());

    }

    @Test
    public void testGetAlgorithmByNameAndKeySize() {
        final String name = "SHA256withRSA";
        final int keySize = 1024;
        Mockito.when(algorithmConfigurationManager.getAlgorithmByNameAndKeySize(name, keySize)).thenReturn(supportedSignatureAlg);
        final Algorithm algorithm = pKIConfigurationService.getAlgorithmByNameAndKeySize(name, keySize);
        assertNotNull(algorithm);
        assertEquals(supportedSignatureAlg.getName(), algorithm.getName());
        Mockito.verify(algorithmConfigurationManager).getAlgorithmByNameAndKeySize(name, keySize);
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmByNameAndKeySize_Invalid_Name() {
        final int keySize = 1024;
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeAlgorithmConfigurationOperations(ActionType.READ);
        Mockito.when(algorithmConfigurationManager.getAlgorithmByNameAndKeySize("invalid", keySize)).thenThrow(new AlgorithmNotFoundException("Algorithm Not found"));
        pKIConfigurationService.getAlgorithmByNameAndKeySize("invalid", keySize);
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmByNameAndKeySize_Exception() {
        final String name = "SHA256withRSA";
        final int keySize = 1024;
        Mockito.when(algorithmConfigurationManager.getAlgorithmByNameAndKeySize(name, keySize)).thenThrow(new AlgorithmNotFoundException());

        pKIConfigurationService.getAlgorithmByNameAndKeySize(name, keySize);

    }

    @Test
    public void testGetAlgorithmsByName() {
        final String name = "SHA256withRSA";
        Mockito.when(algorithmConfigurationManager.getAlgorithmsByName(name)).thenReturn(Arrays.asList(supportedSignatureAlg));

        final List<Algorithm> list = pKIConfigurationService.getAlgorithmsByName(name);
        assertNotNull(list);
        final Algorithm algorithm = list.get(0);
        assertEquals(supportedSignatureAlg.getName(), algorithm.getName());
        Mockito.verify(algorithmConfigurationManager).getAlgorithmsByName(name);
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmsByName_Invalid_Name() {
        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeAlgorithmConfigurationOperations(ActionType.READ);
        Mockito.when(algorithmConfigurationManager.getAlgorithmsByName("invalid")).thenThrow(new AlgorithmNotFoundException("Algorithm Not found"));
        final List<Algorithm> algorithm = pKIConfigurationService.getAlgorithmsByName("invalid");
        assertNull(algorithm);
    }

    @Test(expected = AlgorithmNotFoundException.class)
    public void testGetAlgorithmsByName_Exception() {
        final String name = "SHA256withRSA";
        Mockito.when(algorithmConfigurationManager.getAlgorithmsByName(name)).thenThrow(new AlgorithmNotFoundException());

        final List<Algorithm> algorithm = pKIConfigurationService.getAlgorithmsByName(name);
        assertNotNull(algorithm);
    }

    @Test
    public void testcreateCategory() {
        EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("test");
        Mockito.when(entityCategoryConfigurationManager.createEntityCategory(entityCategory)).thenReturn(entityCategory);
        final EntityCategory entityCategory1 = pKIConfigurationService.createCategory(entityCategory);
        assertNotNull(entityCategory1);
    }

    @Test
    public void testdeleteCategory() {
        EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("test");
        Mockito.doNothing().when(entityCategoryConfigurationManager).deleteEntityCategory(entityCategory);
        pKIConfigurationService.deleteCategory(entityCategory);

    }

    @Test
    public void testgetCategory() {
        EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("test");
        entityCategory.setId(2);
        Mockito.when(entityCategoryConfigurationManager.getEntityCategory(entityCategory)).thenReturn(entityCategory);
        final EntityCategory entityCategory1 = pKIConfigurationService.getCategory(entityCategory);
        assertNotNull(entityCategory1);
    }

    @Test
    public void testUpdateCategory() {
        EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("test");
        entityCategory.setId(2);
        Mockito.when(entityCategoryConfigurationManager.updateEntityCategory(entityCategory)).thenReturn(entityCategory);
        final EntityCategory entityCategory1 = pKIConfigurationService.updateCategory(entityCategory);
        assertNotNull(entityCategory1);
    }

    @Test
    public void testIsCategoryNameAvailable() {
        Mockito.when(entityCategoryConfigurationManager.isNameAvailable("test")).thenReturn(true);
        final boolean isNameAvailable = pKIConfigurationService.isCategoryNameAvailable("test");
        assertTrue(isNameAvailable);

    }

    @Test
    public void testListAllEntityCategories() {

        List<EntityCategory> entityCategories = new ArrayList<EntityCategory>();
        Mockito.when(entityCategoryConfigurationManager.getEntityCategories()).thenReturn(entityCategories);
        final List<EntityCategory> listOfEntityCategories = pKIConfigurationService.listAllEntityCategories();
        assertNotNull(listOfEntityCategories);

    }

    @Test
    public void testUpdateAlgorithms() {

        final List<Algorithm> list = new ArrayList<Algorithm>();
        final Algorithm algorithm = new Algorithm();
        algorithm.setName(supportedMessageDigestAlgorithm.getName());
        algorithm.setKeySize(supportedMessageDigestAlgorithm.getKeySize());
        algorithm.setSupported(false);
        list.add(algorithm);

        Mockito.doNothing().when(algorithmConfigurationManager).updateAlgorithms(list);

        pKIConfigurationService.updateAlgorithms(list);

        Mockito.verify(algorithmConfigurationManager).updateAlgorithms(list);
    }

    @Test
    public void testUpdateAlgorithms_Not_Found() {

        final List<Algorithm> list = new ArrayList<Algorithm>();
        final Algorithm algorithm = new Algorithm();
        algorithm.setName(supportedMessageDigestAlgorithm.getName());
        algorithm.setKeySize(supportedMessageDigestAlgorithm.getKeySize());
        algorithm.setType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
        algorithm.setSupported(false);
        list.add(algorithm);

        Mockito.doNothing().when(configurationManagementAuthorizationManager).authorizeAlgorithmConfigurationOperations(ActionType.UPDATE);
        Mockito.doThrow(new AlgorithmNotFoundException("Algorithm not found")).when(algorithmConfigurationManager).updateAlgorithms(list);
        try {
            pKIConfigurationService.updateAlgorithms(list);
            fail("Should throw AlgorithmNotFoundException");
        } catch (AlgorithmNotFoundException e) {
            // expected
        }
        Mockito.verify(algorithmConfigurationManager).updateAlgorithms(list);
    }
}
