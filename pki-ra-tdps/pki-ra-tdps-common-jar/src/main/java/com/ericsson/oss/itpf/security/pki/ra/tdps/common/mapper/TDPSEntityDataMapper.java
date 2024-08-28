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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;

/**
 * This class is used to map data between JPA model and Entity model
 * 
 * @author tcschdy
 *
 */
public class TDPSEntityDataMapper {

    @Inject
    TDPSCertificateStatusMapper tdpsCertificateStatusMapper;

    @Inject
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    /**
     * Maps the List of JPA model to its corresponding List of Entity model
     * 
     * @param tdpsCertificateInfos
     *            list of TDPSCertificateInfo objects
     * @return list of tdpsEntityDatas objects
     */
    public List<TDPSEntityData> fromModel(final List<TDPSCertificateInfo> tdpsCertificateInfos) {
        final List<TDPSEntityData> tdpsEntityDatas = new ArrayList<>();

        for (final TDPSCertificateInfo tdpsCertificateInfo : tdpsCertificateInfos) {
            final TDPSEntityData tdpsEntityData = fromModel(tdpsCertificateInfo);
            tdpsEntityDatas.add(tdpsEntityData);
        }

        return tdpsEntityDatas;
    }

    /**
     * Maps the List of JPA model to its corresponding List of Entity model
     * 
     * @param tdpsEntityDatas
     *            list of TDPSEntityData objects
     * @return list of tDPSCertificateInfos objects
     */
    public List<TDPSCertificateInfo> toModel(final List<TDPSEntityData> tdpsEntityDatas) {
        final List<TDPSCertificateInfo> tDPSCertificateInfos = new ArrayList<>();

        for (final TDPSEntityData tDPSEntityData : tdpsEntityDatas) {
            final TDPSCertificateInfo tDPSCertificateInfo = toModel(tDPSEntityData);
            tDPSCertificateInfos.add(tDPSCertificateInfo);
        }

        return tDPSCertificateInfos;
    }

    /**
     * Maps the JPA model to its corresponding Entity model
     * 
     * @param tdpsCertificateInfo
     *            TDPSCertificateInfo object
     * @return TDPSEntityData Object
     */
    public TDPSEntityData fromModel(final TDPSCertificateInfo tdpsCertificateInfo) {
        final TDPSEntityData tdpsEntityData = new TDPSEntityData();
        final byte[] pemEncodedCertificate = tdpsCertificateInfo.getEncodedCertificate();

        tdpsEntityData.setCertificate(pemEncodedCertificate);
        tdpsEntityData.setEntityName(tdpsCertificateInfo.getEntityName());
        tdpsEntityData.setEntityType(tdpsEntityTypeMapper.fromModel(tdpsCertificateInfo.getTdpsEntityType()));
        tdpsEntityData.setSerialNo(tdpsCertificateInfo.getSerialNumber());
        tdpsEntityData.setTdpsCertificateStatus(tdpsEntityData.getTdpsCertificateStatus());
        tdpsEntityData.setIssuerName(tdpsCertificateInfo.getIssuerName());
        tdpsEntityData.setTdpsCertificateStatus(tdpsCertificateStatusMapper.fromModel(tdpsCertificateInfo.getTdpsCertificateStatusType()));

        return tdpsEntityData;
    }

    /**
     * Maps the Entity model to its corresponding JPA model
     * 
     * @param tdpsEntityData
     *            TDPSEntityData Object
     * @return TDPSCertificateInfo object
     */
    public TDPSCertificateInfo toModel(final TDPSEntityData tdpsEntityData) {
        final TDPSCertificateInfo tDPSCertificateInfo = new TDPSCertificateInfo();
        tDPSCertificateInfo.setEncodedCertificate(null);
        tDPSCertificateInfo.setEntityName(tdpsEntityData.getEntityName());
        tDPSCertificateInfo.setSerialNumber(tdpsEntityData.getSerialNo());
        tDPSCertificateInfo.setTdpsEntityType(tdpsEntityTypeMapper.toModel(tdpsEntityData.getEntityType()));
        tDPSCertificateInfo.setTdpsCertificateStatusType(tdpsCertificateStatusMapper.toModel(tdpsEntityData.getTdpsCertificateStatus()));
        tDPSCertificateInfo.setIssuerName(tdpsEntityData.getIssuerName());
        return tDPSCertificateInfo;
    }

}
