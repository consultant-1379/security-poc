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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.xml.datatype.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CrlGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class CRLGenerationInfoMapperTest {

    @InjectMocks
    CRLGenerationInfoMapper crlGenerationInfoMapper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    private CrlGenerationInfo crlGenerationInfo;

    private List<CrlGenerationInfo> crlGenerationInfos;

    private CrlGenerationInfoData crlGenerationInfoData;

    private List<CrlGenerationInfoData> crlGenerationInfoDatas;

    private static final String NAME_PATH = "name";
    private static final String TYPE_PATH = "type";
    private static final String SUPPORTED_PATH = "supported";

    private static final String durationString = "PT1H1M30S";

    private Map<String, Object> input = new HashMap<String, Object>();

    private Set<CrlGenerationInfoData> crlGenerationInfoDataList;

    @Before
    public void setUp() {
        crlGenerationInfo = new CrlGenerationInfo();
        crlGenerationInfos = new ArrayList<CrlGenerationInfo>();
        crlGenerationInfoData = new CrlGenerationInfoData();
        crlGenerationInfoDatas = new ArrayList<CrlGenerationInfoData>();

        crlGenerationInfoDataList = new HashSet<CrlGenerationInfoData>();
    }

    @Test(expected = CRLServiceException.class)
    public void testFromAPIModel() throws DatatypeConfigurationException {
        testFromAPIModel_setup();
        List<AlgorithmData> algorithmDataList = new ArrayList<AlgorithmData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, input)).thenReturn(algorithmDataList);
        crlGenerationInfoMapper.fromAPIModel(crlGenerationInfos);
    }

    @Test
    public void testToAPIModel() throws CRLServiceException, CertificateException {
        testToAPIModel_setup();
        crlGenerationInfos = crlGenerationInfoMapper.toAPIModel(crlGenerationInfoDataList);
        Iterator<CrlGenerationInfoData> iterator = crlGenerationInfoDataList.iterator();
        int i = 0;
        while (iterator.hasNext()) {
            CrlGenerationInfoData data = iterator.next();
            Assert.assertEquals(crlGenerationInfos.get(i).getOverlapPeriod().toString(), data.getOverlapPeriod());
            Assert.assertEquals(crlGenerationInfos.get(i).getValidityPeriod().toString(), data.getValidityPeriod());

        }

    }

    private void testToAPIModel_setup() {
        crlGenerationInfoData = new CrlGenerationInfoData();
        crlGenerationInfoData.setId(123);
        crlGenerationInfoData.setVersion(2);
        crlGenerationInfoData.setOverlapPeriod("P18088DT5H25M21.000S");
        crlGenerationInfoData.setValidityPeriod("P18088DT5H25M21.000S");
        AlgorithmData signatureAlgorithmData = new AlgorithmData();
        signatureAlgorithmData.setId(654);
        signatureAlgorithmData.setName("TCS");
        crlGenerationInfoData.setSignatureAlgorithm(signatureAlgorithmData);
        crlGenerationInfoDataList.add(crlGenerationInfoData);

    }

    private void testFromAPIModel_setup() throws DatatypeConfigurationException {
        crlGenerationInfo.setId(123);
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        formatter.setLenient(false);
        Date d = null;
        try {
            d = formatter.parse("2019-07-11 10:55:21");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
        Duration validity = datatypeFactory.newDuration(d.getTime());

        crlGenerationInfo.setOverlapPeriod(validity);
        crlGenerationInfo.setValidityPeriod(validity);
        ;
        crlGenerationInfo.setSkewCrlTime(validity);
        crlGenerationInfo.setVersion(CRLVersion.V2);
        Algorithm signatureAlgorithm = new Algorithm();
        signatureAlgorithm.setId(654);
        signatureAlgorithm.setName("TCS");
        crlGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
        crlGenerationInfos.add(crlGenerationInfo);
        input.put(NAME_PATH, "TCS");
        input.put(TYPE_PATH, AlgorithmType.SIGNATURE_ALGORITHM.getId());
        input.put(SUPPORTED_PATH, true);
    }

}
