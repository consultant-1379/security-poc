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
package com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.common.SetUpData;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CRLInfoMapper;

/**
 * This class used to test CRLInfoMapper functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLInfoMapperTest extends SetUpData {

    @InjectMocks
    CRLInfoMapper crlInfoMapper;

    @Mock
    CACertificateInfoMapper caCertificateInfoMapper;

    private CRLInfo crlInfo;
    private CRLInfo crlInfoReturn;
    private List<CRLInfo> crlInfoList;
    private List<CRLInfo> crlInfoListReturn;
    private CACertificateInfo caCertificateInfo;
    private CDPSEntityData cdpsEntityData;
    private CDPSEntityData cdpsEntityDataReturn;
    private List<CDPSEntityData> cdpsEntityDatas;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caCertificateInfo = prepareCACertificateInfo();

        crlInfo = prepareCRLInfo();

        crlInfoList = prepareCRLInfoList();

        cdpsEntityData = prepareCDPSEntityData();

        cdpsEntityDatas = prepareCDPSEntityDataList();
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CRLInfoMapper#fromModel(java.util.List)} .
     */
    @Test
    public void testFromModelListOfCRLInfo() {

        cdpsEntityDatas = crlInfoMapper.fromModel(crlInfoList);

        assertNotNull(cdpsEntityDatas);
        assertEquals(crlInfoList.get(0).getCaCertificateInfo().getCaName(), cdpsEntityDatas.get(0).getCaName());
        assertEquals(crlInfoList.get(0).getCaCertificateInfo().getCertificateSerialNumber(), cdpsEntityDatas.get(0).getCertSerialNumber());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CRLInfoMapper#fromModel(com.ericsson.oss.itpf.security.pki.ra.cdps.cdt.CRLInfo)} .
     */
    @Test
    public void testFromModelCRLInfo() {

        cdpsEntityDataReturn = crlInfoMapper.fromModel(crlInfo);

        assertNotNull(cdpsEntityDataReturn);
        assertEquals(crlInfo.getCaCertificateInfo().getCaName(), cdpsEntityDataReturn.getCaName());
        assertEquals(crlInfo.getCaCertificateInfo().getCertificateSerialNumber(), cdpsEntityDataReturn.getCertSerialNumber());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CRLInfoMapper#toModel(java.util.List)} .
     */
    @Test
    public void testToModelListOfCDPSEntityData() {

        Mockito.when(caCertificateInfoMapper.toModel(cdpsEntityData)).thenReturn(caCertificateInfo);
        crlInfoListReturn = crlInfoMapper.toModel(cdpsEntityDatas);

        assertNotNull(crlInfoListReturn);
        assertEquals(cdpsEntityDatas.get(0).getCaName(), crlInfoListReturn.get(0).getCaCertificateInfo().getCaName());
        assertEquals(cdpsEntityDatas.get(0).getCertSerialNumber(), crlInfoListReturn.get(0).getCaCertificateInfo().getCertificateSerialNumber());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CRLInfoMapper#toModel(com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData)}
     * .
     */
    @Test
    public void testToModelCDPSEntityData() {

        Mockito.when(caCertificateInfoMapper.toModel(cdpsEntityData)).thenReturn(caCertificateInfo);
        crlInfoReturn = crlInfoMapper.toModel(cdpsEntityData);

        assertNotNull(crlInfoReturn);
        assertEquals(cdpsEntityData.getCaName(), crlInfoReturn.getCaCertificateInfo().getCaName());
        assertEquals(cdpsEntityData.getCertSerialNumber(), crlInfoReturn.getCaCertificateInfo().getCertificateSerialNumber());

    }

}
