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
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.common.SetUpData;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper;

/**
 * This class used to test CACertificateInfoMapper functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CACertificateInfoMapperTest extends SetUpData {

    @InjectMocks
    CACertificateInfoMapper caCertificateInfoMapper;

    private CACertificateInfo caCertificateInfo;
    private CACertificateInfo caCertificateInfoReturn;
    private List<CACertificateInfo> caCertificateInfos;
    private List<CACertificateInfo> caCertificateInfosReturn;
    private List<CACertificateInfo> caCertificateInfosEmpty;

    private CDPSEntityData cdpsEntityData;
    private CDPSEntityData cdpsEntityDataReturn;
    private List<CDPSEntityData> cdpsEntityDatas;
    private List<CDPSEntityData> cdpsEntityDatasReturn;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caCertificateInfo = prepareCACertificateInfo();

        caCertificateInfos = prepareCACertificateInfoList();

        cdpsEntityData = prepareCDPSEntityData();

        cdpsEntityDatas = prepareCDPSEntityDataList();
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper#fromModel(java.util.List)} .
     */
    @Test
    public void testFromModelListOfCACertificateInfo() {

        cdpsEntityDatasReturn = caCertificateInfoMapper.fromModel(caCertificateInfos);

        assertNotNull(cdpsEntityDatasReturn);
        assertEquals(caCertificateInfos.get(0).getCaName(), cdpsEntityDatasReturn.get(0).getCaName());
        assertEquals(caCertificateInfos.get(0).getCertificateSerialNumber(), cdpsEntityDatasReturn.get(0).getCertSerialNumber());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper#fromModel(java.util.List)} .
     */
    @Test
    public void testFromModelListOfCACertificateInfoEmpty() {

        cdpsEntityDatasReturn = caCertificateInfoMapper.fromModel(caCertificateInfosEmpty);

        assertEquals(null, cdpsEntityDatasReturn);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper#fromModel(com.ericsson.oss.itpf.security.pki.ra.cdps.cdt.CACertificateInfo)} .
     */
    @Test
    public void testFromModelCACertificateInfo() {

        cdpsEntityDataReturn = caCertificateInfoMapper.fromModel(caCertificateInfo);

        assertNotNull(cdpsEntityDataReturn);
        assertEquals(caCertificateInfo.getCaName(), cdpsEntityDataReturn.getCaName());
        assertEquals(caCertificateInfo.getCertificateSerialNumber(), cdpsEntityDataReturn.getCertSerialNumber());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper#toModel(java.util.List)} .
     */
    @Test
    public void testToModelListOfCDPSEntityData() {

        caCertificateInfosReturn = caCertificateInfoMapper.toModel(cdpsEntityDatas);

        assertNotNull(caCertificateInfosReturn);
        assertEquals(cdpsEntityDatas.get(0).getCaName(), caCertificateInfosReturn.get(0).getCaName());
        assertEquals(cdpsEntityDatas.get(0).getCertSerialNumber(), caCertificateInfosReturn.get(0).getCertificateSerialNumber());

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.cdps.common.persistence.modelmapper.CACertificateInfoMapper#toModel(com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData)} .
     */
    @Test
    public void testToModelCDPSEntityData() {

        caCertificateInfoReturn = caCertificateInfoMapper.toModel(cdpsEntityData);

        assertNotNull(caCertificateInfoReturn);
        assertEquals(cdpsEntityData.getCaName(), caCertificateInfoReturn.getCaName());
        assertEquals(cdpsEntityData.getCertSerialNumber(), caCertificateInfoReturn.getCertificateSerialNumber());
    }

}
