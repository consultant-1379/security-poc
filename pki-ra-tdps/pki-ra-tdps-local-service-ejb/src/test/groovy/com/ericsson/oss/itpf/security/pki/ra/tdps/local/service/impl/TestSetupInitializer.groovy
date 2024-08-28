/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.impl;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSCertificateStatusMapper
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSEntityTypeMapper
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility

import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.List

import javax.inject.Inject

/**
 * This class is responsible for mocking the certificates in the DB.
 *
 *  @author xvadyas
 *
 */

class TestSetupInitializer {

    @Inject
    TDPSEntityTypeMapper tDPSEntityTypeMapper

    @Inject
    TDPSCertificateStatusMapper tDPSCertificateStatusMapper

    public List<TDPSEntityData> getEntityDetails(final TDPSCertificateInfo tdpsCertificateInfo, final String filePath){

        List<TDPSEntityData> tdpsEntityDataList = new ArrayList<TDPSEntityData>()
        List<TDPSEntityData> tdpsEntityDataList_Empty = new ArrayList<TDPSEntityData>()

        tDPSEntityTypeMapper = new TDPSEntityTypeMapper()
        tDPSCertificateStatusMapper = new TDPSCertificateStatusMapper()

        final TDPSEntityData tDPSEntityData = new TDPSEntityData()
        tDPSEntityData.setEntityName(tdpsCertificateInfo.getEntityName())
        tDPSEntityData.setEntityType(tDPSEntityTypeMapper.fromModel(tdpsCertificateInfo.getTdpsEntityType()))
        tDPSEntityData.setIssuerName(tdpsCertificateInfo.getIssuerName())
        tDPSEntityData.setSerialNo(tdpsCertificateInfo.getSerialNumber())
        tDPSEntityData.setTdpsCertificateStatus(tDPSCertificateStatusMapper.fromModel(tdpsCertificateInfo.getTdpsCertificateStatusType()))
        tDPSEntityData.setCertificate(getTDPSCert(filePath))
        tdpsEntityDataList.add(tDPSEntityData)
        final X509Certificate certificate = CertificateUtility.getCertificateFromByteArray(getTDPSCert(filePath))
        String issuerName = StringUtility.getCNfromDN(certificate.issuerDN.name)
        if(tdpsCertificateInfo.getIssuerName().equalsIgnoreCase(issuerName)){
            return tdpsEntityDataList
        }else{
            return tdpsEntityDataList_Empty
        }
    }

    public TDPSEntityData getTDPSEntityData(final String entityName, final TDPSEntity entityType, final String issuerName, final String serialNo, final TDPSCertificateStatus tdpsCertificateStatus, final String filePath){

        final TDPSEntityData tDPSEntityData = new TDPSEntityData()

        tDPSEntityData.setEntityName(entityName)
        tDPSEntityData.setEntityType(entityType)
        tDPSEntityData.setIssuerName(issuerName)
        tDPSEntityData.setSerialNo(serialNo)
        tDPSEntityData.setTdpsCertificateStatus(tdpsCertificateStatus)
        tDPSEntityData.setCertificate(getTDPSCert(filePath))
        return tDPSEntityData
    }

    private byte[] getTDPSCert(final String filePath) {
        X509Certificate tDPSCert = null
        FileInputStream fileInputStream
        String tDPSCertPath = null
        tDPSCertPath = TDPSLocalServiceBeanTest.class.getResource(filePath).getPath()
       final  CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509")
        fileInputStream = new FileInputStream(tDPSCertPath)
        tDPSCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream)
        return tDPSCert.getEncoded()
    }
}
