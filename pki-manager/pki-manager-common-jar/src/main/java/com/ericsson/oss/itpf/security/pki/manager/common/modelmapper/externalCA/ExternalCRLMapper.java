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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA;

import java.io.IOException;
import java.security.cert.CRLException;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
//import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;


/**
 * Converts CRL api model to ExternalCRLInfoData jpa model.
 *
 */
public class ExternalCRLMapper {

    /**
     * Convert CRL Object model to ExternalCRLInfoData entity object.
     *
     * @param ExternalCRLInfo
     *            The CRL object.
     *
     * @return ExternalCRLInfoData object.
     */
    public ExternalCRLInfoData fromAPIToModel(final ExternalCRLInfo crl) throws ExternalCRLEncodedException {
        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setNextUpdate(crl.getNextUpdate());
        externalCrlInfoData.setAutoUpdate(crl.isAutoUpdate());
        final Integer checkTimer = crl.getAutoUpdateCheckTimer();
        externalCrlInfoData.setAutoUpdateCheckTimer(checkTimer);
        externalCrlInfoData.setUpdateUrl(crl.getUpdateURL());
        try {
            externalCrlInfoData.setCrl(crl.getX509CRL().retrieveCRL().getEncoded());
        } catch (final CRLException e) {
            throw new ExternalCRLEncodedException("Problem with encoded CRL ", e);
        }
        return externalCrlInfoData;
    }

    /**
     * Convert ExternalCRLInfoData entity Object to CRL Object Model.
     *
     * @param ExternalCRLInfoData
     *            The CRL Data entity object.
     *
     * @return CRL object model.
     * @throws ExternalCRLEncodedException
     *             Thrown when the CRL is not correct.
     */
    public ExternalCRLInfo toAPIFromModel(final ExternalCRLInfoData externalCrlInfoData) throws ExternalCRLEncodedException {
        final ExternalCRLInfo crl = new ExternalCRLInfo();
        crl.setId(externalCrlInfoData.getId());
        crl.setNextUpdate(externalCrlInfoData.getNextUpdate());
        crl.setAutoUpdate(externalCrlInfoData.isAutoUpdate());
        final Integer checkTimer = externalCrlInfoData.getAutoUpdateCheckTimer();

        crl.setAutoUpdateCheckTimer(checkTimer);
        crl.setUpdateURL(externalCrlInfoData.getUpdateUrl());

        X509CRLHolder x509CrlHolder;
        try {
            x509CrlHolder = new X509CRLHolder(externalCrlInfoData.getCrl());
            crl.setX509CRL(x509CrlHolder);
        } catch (final IOException | CRLException e) {
            throw new ExternalCRLEncodedException("Problem with CRL Converter ", e);
        }

        return crl;
    }
}
