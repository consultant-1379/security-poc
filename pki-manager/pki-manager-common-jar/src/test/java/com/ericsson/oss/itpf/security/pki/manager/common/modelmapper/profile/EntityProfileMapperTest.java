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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile;

import static org.junit.Assert.assertSame;

import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmCategory;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * Test class for {@link EntityProfileMapper}
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityProfileMapperTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityProfileMapper.class);

    @InjectMocks
    private EntityProfileMapper entityProfileMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    TrustProfileMapper trustProfileMapper;

    @Mock
    CertificateProfileMapper certificateProfileMapper;

    private EntityProfile entityProfile = null;
    private EntityProfileData entityProfileData = null;

    AlgorithmData algorithmData = null;
    private CertificateProfileSetUpData certificateProfileSetUpToTest;

    private static final String NAME_PATH = "name";
    private static final String TYPE_PATH = "type";
    private static final String KEYSIZE_PATH = "keySize";
    private static final String SUPPORTED_PATH = "supported";
    private static final String CATEGORIES_PATH = "categories";

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        final EntityProfileSetUpData entityProfileSetUpToTest = new EntityProfileSetUpData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();
        entityProfileData = entityProfileSetUpToTest.getEntityProfileData();

    }

    /**
     * Method to test ToAPIModel method in positive scenario.
     */
    @Test
    public void testToAPIModel() throws DatatypeConfigurationException {

        final Map<String, Object> input = new HashMap<String, Object>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());

        input.put(NAME_PATH, entityProfile.getKeyGenerationAlgorithm().getName());
        input.put(TYPE_PATH, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId());
        input.put(KEYSIZE_PATH, entityProfile.getKeyGenerationAlgorithm().getKeySize());
        input.put(SUPPORTED_PATH, new Boolean(true));
        input.put(CATEGORIES_PATH, categories);

        algorithmData = certificateProfileSetUpToTest.getCertificateProfileData().getSignatureAlgorithm();
        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(algorithmData);

        final EntityProfile entityProfile = entityProfileMapper.toAPIFromModel(entityProfileData);
        assertSame(entityProfile.getName(), entityProfileData.getName());

    }

    /**
     * Method to test FromAPIModel method in positive scenario.
     */
    @Test
    public void TestFromAPIModel() {

        final EntityProfileData entityProfileData = entityProfileMapper.fromAPIToModel(entityProfile);
        assertSame(entityProfile.getName(), entityProfileData.getName());
    }

}
