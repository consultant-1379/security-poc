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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl;

/**
 * Test Class for CRLGenerationInfoMapper.
 */
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.data.CrlGenerationInfoSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CrlGenerationInfoData;

@RunWith(MockitoJUnitRunner.class)
public class CRLGenerationInfoMapperTest {
    @InjectMocks
    CRLGenerationInfoMapper cRLGenerationInfoMapper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateModelMapper certificateModelMapper;

    private static List<CrlGenerationInfo> crlGenerationInfoList;
    private static Set<CrlGenerationInfoData> crlGenerationInfoDataSet;
    private static CrlGenerationInfo crlGenerationInfo;
    private static CrlGenerationInfoData crlGenerationInfoData;
    private static AlgorithmData algorithmData;

    /**
     * Prepares initial Data.
     */
    @Before
    public void setUpData() {

        algorithmData = new AlgorithmData();
        crlGenerationInfo = CrlGenerationInfoSetUpData.getCrlGenerationInfo();
        crlGenerationInfoData = CrlGenerationInfoSetUpData.getCrlGenerationInfoData();
        crlGenerationInfoList = new ArrayList<CrlGenerationInfo>();
        crlGenerationInfoList.add(crlGenerationInfo);
        crlGenerationInfoDataSet = new HashSet<CrlGenerationInfoData>();
        crlGenerationInfoDataSet.add(crlGenerationInfoData);
    }

    /**
     * Method to test toModelFromAPI.
     */
    @Test
    public void testToModelFromAPI() {
        Mockito.when(cRLGenerationInfoMapper.getSignatureAlgorithmData(crlGenerationInfo.getSignatureAlgorithm().getName())).thenReturn(algorithmData);
        final Set<CrlGenerationInfoData> associatedCrl = cRLGenerationInfoMapper.toModelFromAPI(crlGenerationInfoList);
        assertNotNull(associatedCrl);
        assertEquals(1, associatedCrl.size());
    }

    /**
     * Method to test Occurrence of CommonRuntimeException.
     * 
     * @return Exception.
     */
    @Test(expected = CommonRuntimeException.class)
    public void testToAPIFromModel_CommonRuntimeException() throws Exception {
        crlGenerationInfoData.setCrlExtensionsJSONData("{XYZ}");
        cRLGenerationInfoMapper.toAPIFromModel(crlGenerationInfoDataSet);
    }

    /**
     * Method to test toAPIFromModel.
     */
    @Test
    public void testToAPIFromModel() throws Exception {
        final List<CrlGenerationInfo> crlGenerationInfoList = cRLGenerationInfoMapper.toAPIFromModel(crlGenerationInfoDataSet);
        assertNotNull(crlGenerationInfoList);
        assertEquals(1, crlGenerationInfoList.size());
    }

}
