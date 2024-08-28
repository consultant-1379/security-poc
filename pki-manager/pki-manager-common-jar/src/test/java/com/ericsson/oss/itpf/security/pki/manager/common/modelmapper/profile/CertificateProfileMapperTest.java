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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmCategory;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLGenerationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;

/**
 * Test class for {@link CertificateProfileMapper}
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class CertificateProfileMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateProfileMapper.class);

    @InjectMocks
    private CertificateProfileMapper certificateProfileMapper;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private CAEntityMapper caEntityMapper;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    private CRLGenerationInfoMapper cRLGenerationInfoMapper;

    public final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";
    private CertificateProfileSetUpData certificateProfileSetUpToTest;
    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;
    private EntitiesSetUpData entitiesSetUpData;

    private List<CrlGenerationInfo> crlGenerationInfo = new ArrayList<CrlGenerationInfo>();

    private static final String NAME_PATH = "name";
    private static final String SUPPORTED_PATH = "supported";
    private static final String CATEGORIES_PATH = "categories";

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        entitiesSetUpData = new EntitiesSetUpData();
        certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();
        // algorithm = certificateProfileSetUpToTest.getCertificateProfile().getSignatureAlgorithm();

    }

    /**
     * Method to test toAPIModel method in positive scenario.
     */
    @Test
    public void testToAPIModel() throws DatatypeConfigurationException {
        final CAEntity caEnt = entitiesSetUpData.getCaEntity();
        Mockito.when(caEntityMapper.toAPIFromModel(certificateProfileData.getIssuerData())).thenReturn(caEnt);
        try {
            Mockito.when(cRLGenerationInfoMapper.toAPIFromModel(Mockito.anySet())).thenReturn(crlGenerationInfo);
        } catch (InvalidCRLGenerationInfoException | CertificateException | IOException e) {
            fail(e.getMessage());
        }
        final CertificateProfile certificateProfile1 = certificateProfileMapper.toAPIFromModel(certificateProfileData);
        assertEquals(certificateProfile.getName(), certificateProfile1.getName());
    }

    /**
     * Method to test fromAPIModel method in positive scenario.
     */
    @Test
    public void testFromAPIModel() throws Exception {

        final Map<String, Object> input = new HashMap<String, Object>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.KEY_IDENTIFIER.getId());

        input.put(NAME_PATH, certificateProfile.getSignatureAlgorithm().getName());
        input.put(SUPPORTED_PATH, new Boolean(true));
        input.put(CATEGORIES_PATH, categories);

        final AlgorithmData algorithmData = certificateProfileSetUpToTest.getCertificateProfileData().getSignatureAlgorithm();
        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(algorithmData);
        final CertificateProfileData certificateProfileData1 = certificateProfileMapper.fromAPIToModel(certificateProfile);
        assertEquals(certificateProfileData.getName(), certificateProfileData1.getName());
    }

    /**
     * Method to test fromAPIModel method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testFromAPIModelWithException() throws Exception {
        final Map<String, Object> input = new HashMap<String, Object>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.KEY_IDENTIFIER.getId());

        input.put(NAME_PATH, certificateProfile.getSignatureAlgorithm().getName());
        input.put(SUPPORTED_PATH, new Boolean(true));
        input.put(CATEGORIES_PATH, categories);
        final AlgorithmData algorithmData = certificateProfileSetUpToTest.getCertificateProfileData().getSignatureAlgorithm();

        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(algorithmData);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "ENMRootCA", "certificateAuthorityData.name")).thenThrow(new PersistenceException());

        final CertificateProfileData certificateProfileData = certificateProfileMapper.fromAPIToModel(certificateProfile);
        assertEquals(certificateProfileData.getName(), certificateProfile.getName());
    }
}
