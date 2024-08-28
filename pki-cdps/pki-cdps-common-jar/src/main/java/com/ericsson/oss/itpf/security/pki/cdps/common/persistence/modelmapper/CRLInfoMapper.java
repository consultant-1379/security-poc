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

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;

/**
 * This Class prepares the CRL Info to map using list of CRLInfo and CDPSEntityData
 * 
 * @author xjagcho
 *
 */
public class CRLInfoMapper {
    @Inject
    CACertificateInfoMapper caCertificateInfoMapper;

    /**
     * This method process the list crlInfos
     * 
     * @param crlInfos
     *            it contains list of CRLInfo and it holds CACertificateInfo it contains caName and serialNumber and encoded crl
     * @return List of CDPSEntityData
     */
    public List<CDPSEntityData> fromModel(final List<CRLInfo> crlInfos) {
        final List<CDPSEntityData> cdpsEntityDatas = new ArrayList<CDPSEntityData>();

        for (CRLInfo crlInfo : crlInfos) {
            final CDPSEntityData cdpsEntityData = fromModel(crlInfo);
            cdpsEntityDatas.add(cdpsEntityData);
        }

        return cdpsEntityDatas;
    }

    /**
     * This method process the caCertificateInfo object
     * 
     * @param crlInfo
     *            it holds CACertificateInfo it contains caName and serialNumber and encoded crl
     * @return List of cdpsEntityData
     */
    public CDPSEntityData fromModel(final CRLInfo crlInfo) {
        final CDPSEntityData cdpsEntityData = new CDPSEntityData();

        cdpsEntityData.setCaName(crlInfo.getCaCertificateInfo().getCaName());
        cdpsEntityData.setCertSerialNumber(crlInfo.getCaCertificateInfo().getCertificateSerialNumber());
        cdpsEntityData.setCrl(crlInfo.getEncodedCRL());

        return cdpsEntityData;
    }

    /**
     * This method process the list of cdpsEntityData
     * 
     * @param cdpsEntityData
     *            it holds list of CDPSEntityData it contains id,caName,certificate serialNumber and CRL
     * @return list of crlInfos object
     */
    public List<CRLInfo> toModel(final List<CDPSEntityData> cdpsEntityDatas) {
        final List<CRLInfo> crlInfos = new ArrayList<CRLInfo>();

        for (CDPSEntityData cdpsEntityData : cdpsEntityDatas) {
            final CRLInfo crlInfo = toModel(cdpsEntityData);
            crlInfos.add(crlInfo);
        }

        return crlInfos;
    }

    /**
     * This method process the cdpsEntityData
     * 
     * @param cdpsEntityData
     *            it contains id,caName,certificate serialNumber and CRL
     * @return crlInfo object
     */
    public CRLInfo toModel(final CDPSEntityData cdpsEntityData) {
        final CRLInfo crlInfo = new CRLInfo();

        crlInfo.setCaCertificateInfo(caCertificateInfoMapper.toModel(cdpsEntityData));
        crlInfo.setEncodedCRL(cdpsEntityData.getCrl());

        return crlInfo;
    }
}