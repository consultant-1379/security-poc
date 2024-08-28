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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

@RunWith(MockitoJUnitRunner.class)
public class TDPSEntityDataMapperTest {

    @InjectMocks
    TDPSEntityDataMapper tDPSEntityDataMapper;

    @Mock
    TDPSCertificateStatusMapper tdpsCertificateStatusMapper;

    @Mock
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    TDPSCertificateInfo tDPSCertificateInfo;

    @Test
    public void testFromModel() throws CertificateException, FileNotFoundException {

        setUpTDPSCertificateInfo();

        List<TDPSCertificateInfo> listTdpsCertificateInfos = getMockEntityList();

        TDPSEntity tdpsEntity = TDPSEntity.CA_ENTITY;

        Mockito.when(tdpsEntityTypeMapper.fromModel(tDPSCertificateInfo.getTdpsEntityType())).thenReturn(tdpsEntity);

        TDPSCertificateStatus tdpsCertificateStatus = TDPSCertificateStatus.ACTIVE;
        Mockito.when(tdpsCertificateStatusMapper.fromModel(tDPSCertificateInfo.getTdpsCertificateStatusType())).thenReturn(tdpsCertificateStatus);

        List<TDPSEntityData> tdpsEntityDatas = tDPSEntityDataMapper.fromModel(listTdpsCertificateInfos);

        TDPSEntityData tdpsEntityData = tdpsEntityDatas.get(0);

        Assert.assertEquals(TDPSEntity.CA_ENTITY + "", tdpsEntityData.getEntityType() + "");

    }

    /**
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    private void setUpTDPSCertificateInfo() throws CertificateException, FileNotFoundException {
        tDPSCertificateInfo = new TDPSCertificateInfo();
        byte[] encodedCertificate = getTDPSCerts();
        tDPSCertificateInfo.setEncodedCertificate(encodedCertificate);
        tDPSCertificateInfo.setEntityName("name");
        tDPSCertificateInfo.setSerialNumber("1");

        TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.ACTIVE;
        tDPSCertificateInfo.setTdpsCertificateStatusType(tdpsCertificateStatusType);

        TDPSEntityType tdpsEntityType = TDPSEntityType.CA_ENTITY;
        tDPSCertificateInfo.setTdpsEntityType(tdpsEntityType);
    }

    public List<TDPSCertificateInfo> getMockEntityList() {
        List<TDPSCertificateInfo> listTdpsCertificateInfos = new ArrayList<TDPSCertificateInfo>();
        listTdpsCertificateInfos.add(tDPSCertificateInfo);

        return listTdpsCertificateInfos;

    }

    @Test
    public void testToModel() {
        TDPSEntityData tdpsEntityData = setUpTDPSEntityData();

        List<TDPSEntityData> listTdpsEntityDatas = new ArrayList<TDPSEntityData>();
        listTdpsEntityDatas.add(tdpsEntityData);

        TDPSEntityType tdpsEntityType = TDPSEntityType.CA_ENTITY;
        Mockito.when(tdpsEntityTypeMapper.toModel(tdpsEntityData.getEntityType())).thenReturn(tdpsEntityType);

        TDPSCertificateStatusType tdpsCertificateStatusType = TDPSCertificateStatusType.ACTIVE;
        Mockito.when(tdpsCertificateStatusMapper.toModel(tdpsEntityData.getTdpsCertificateStatus())).thenReturn(tdpsCertificateStatusType);

        List<TDPSCertificateInfo> tDPSCertificateInfos = tDPSEntityDataMapper.toModel(listTdpsEntityDatas);

        TDPSCertificateInfo tdpsCertificateInfo = tDPSCertificateInfos.get(0);
        Assert.assertEquals(TDPSEntityType.CA_ENTITY + "", tdpsCertificateInfo.getTdpsEntityType() + "");
    }

    private TDPSEntityData setUpTDPSEntityData() {
        TDPSEntityData tdpsEntityData = new TDPSEntityData();
        TDPSCertificateStatus tdpsCertificateStatus = TDPSCertificateStatus.ACTIVE;
        TDPSEntity tdpsEntity = TDPSEntity.CA_ENTITY;
        tdpsEntityData.setEntityName("name");
        tdpsEntityData.setEntityType(tdpsEntity);
        tdpsEntityData.setSerialNo("1");
        tdpsEntityData.setTdpsCertificateStatus(tdpsCertificateStatus);
        return tdpsEntityData;
    }

    public static byte[] getTDPSCerts() throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory;
        X509Certificate tDPSCert;
        FileInputStream fileInputStream;
        String tDPSCertPath = null;

        tDPSCertPath = TDPSEntityDataMapperTest.class.getResource("/Certificates/verifyDigiSignature_vendorCerts/factory.crt").getPath();
        certificateFactory = CertificateFactory.getInstance("X.509");
        fileInputStream = new FileInputStream(tDPSCertPath);
        tDPSCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        return tDPSCert.getEncoded();
    }

}
