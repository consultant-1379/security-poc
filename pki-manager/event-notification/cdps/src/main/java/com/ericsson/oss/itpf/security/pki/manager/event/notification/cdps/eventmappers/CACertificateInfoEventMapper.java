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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;

/**
 * This Class prepares the CACertificateInformation and CACertificateIdentifier to map using list of CACertificateIdentifier and CACertificateInfo
 * 
 * @author xjagcho
 *
 */
public class CACertificateInfoEventMapper {

    /**
     * This method process the list of caCertificateInfos
     * 
     * @param caCertificateInfos
     *            it contains list of CACertificateInfo it contains caName and serialNumber
     * 
     * @return List of CACertificateIdentifier
     */
    public List<CACertificateIdentifier> toModel(final List<CACertificateInfo> caCertificateInfos) {
        final List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();

        for (CACertificateInfo caCertificateInfo : caCertificateInfos) {
            final CACertificateIdentifier caCertificateIdentifier = toModel(caCertificateInfo);
            caCertificateIdentifiers.add(caCertificateIdentifier);
        }

        return caCertificateIdentifiers;
    }

    /**
     * This method process the caCertificateInfo object
     * 
     * @param caCertificateInfo
     *            it holds caName and serialNumber
     * 
     * @return CACertificateIdentifier
     */
    public CACertificateIdentifier toModel(final CACertificateInfo caCertificateInfo) {
        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();

        caCertificateIdentifier.setCaName(caCertificateInfo.getCaName());
        caCertificateIdentifier.setCerficateSerialNumber(caCertificateInfo.getCertificateSerialNumber());

        return caCertificateIdentifier;
    }

    /**
     * This method process the CACertificateIdentifier object
     * 
     * @param caCertificateIdentifier
     *            it contains CAName and Certificate Serial Number
     * @return CACertificateInfo
     */
    public CACertificateInfo fromModel(final CACertificateIdentifier caCertificateIdentifier) {
        final CACertificateInfo caCertificateInfo = new CACertificateInfo();

        caCertificateInfo.setCaName(caCertificateIdentifier.getCaName());
        caCertificateInfo.setCertificateSerialNumber(caCertificateIdentifier.getCerficateSerialNumber());

        return caCertificateInfo;
    }

    /**
     * This method process the list of CACertificateIdentifier object
     * 
     * @param caCertificateIdentifiers
     *            it holds list CACertificateIdentifier it contains CAName and Certificate Serial Number
     * @return list of CACertificateInfo
     */
    public List<CACertificateInfo> fromModel(final List<CACertificateIdentifier> caCertificateIdentifiers) {
        final List<CACertificateInfo> caCertificateInfos = new ArrayList<CACertificateInfo>();

        for (CACertificateIdentifier caCertificateIdentifier : caCertificateIdentifiers) {
            final CACertificateInfo caCertificateInfo = fromModel(caCertificateIdentifier);
            caCertificateInfos.add(caCertificateInfo);
        }

        return caCertificateInfos;
    }
}