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

import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;

/**
 * This Class prepares the CA CertificateInfo to map using list of CACertificateInfo and CDPSEntityData
 * 
 * @author xjagcho
 *
 */
public class CACertificateInfoMapper {
    /**
     * This method process the list caCertificateInfos from Model
     * 
     * @param caCertificateInfos
     *            it contains list of CACertificateInfo and it holds caName and serialNumber
     * @return List of CDPSEntityData
     */
    public List<CDPSEntityData> fromModel(final List<CACertificateInfo> caCertificateInfos) {
        if (caCertificateInfos == null) {
            return null;
        }

        final List<CDPSEntityData> cdpsEntityDatas = new ArrayList<CDPSEntityData>();

        for (CACertificateInfo caCertificateInfo : caCertificateInfos) {
            final CDPSEntityData cdpsEntityData = fromModel(caCertificateInfo);
            cdpsEntityDatas.add(cdpsEntityData);
        }

        return cdpsEntityDatas;
    }

    /**
     * This method process the caCertificateInfo object from Model
     * 
     * @param caCertificateInfos
     *            it contains list of CACertificateInfo and it holds caName and serialNumber
     * @return List of cdpsEntityData
     */
    public CDPSEntityData fromModel(final CACertificateInfo caCertificateInfo) {
        final CDPSEntityData cdpsEntityData = new CDPSEntityData();

        cdpsEntityData.setCaName(caCertificateInfo.getCaName());
        cdpsEntityData.setCertSerialNumber(caCertificateInfo.getCertificateSerialNumber());

        return cdpsEntityData;
    }

    /**
     * This method process the list of cdpsEntityData to Model
     * 
     * @param cdpsEntityData
     *            it contains id,caName,certificate serialNumber and CRL
     * @return list of caCertificateInfos object
     */
    public List<CACertificateInfo> toModel(final List<CDPSEntityData> cdpsEntityDatas) {
        final List<CACertificateInfo> caCertificateInfos = new ArrayList<CACertificateInfo>();

        for (CDPSEntityData cdpsEntityData : cdpsEntityDatas) {
            final CACertificateInfo caCertificateInfo = toModel(cdpsEntityData);
            caCertificateInfos.add(caCertificateInfo);
        }

        return caCertificateInfos;
    }

    /**
     * This method process the cdpsEntityData to Model
     * 
     * @param cdpsEntityData
     *            it contains id,caName,certificate serialNumber and CRL
     * @return caCertificateInfo object
     */
    public CACertificateInfo toModel(final CDPSEntityData cdpsEntityData) {
        final CACertificateInfo caCertificateInfo = new CACertificateInfo();

        caCertificateInfo.setCaName(cdpsEntityData.getCaName());
        caCertificateInfo.setCertificateSerialNumber(cdpsEntityData.getCertSerialNumber());

        return caCertificateInfo;
    }
}