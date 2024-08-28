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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

public class CRLInfoMapper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateModelMapper modelMapper;

    /**
     * Convert CRL Object model to CRLData entity object.
     *
     * @param crlInfo
     *            The CRL object.
     *
     * @return CRLData object.
     * @throws CRLServiceException
     *             thrown, if any database failures occurs in case of CRL operations.
     */
    public CRLInfoData fromAPIToModel(final CRLInfo crlInfo) throws CRLServiceException {
        final CRLInfoData crlInfoData = new CRLInfoData();
        try {
            final CertificateData certificateData = persistenceManager.findEntity(CertificateData.class, crlInfo.getIssuerCertificate().getId());
            CRLData crlData = persistenceManager.findEntity(CRLData.class, crlInfo.getCrl().getId());
            crlInfoData.setId(crlInfo.getId());
            crlInfoData.setCrlNumber(crlInfo.getCrlNumber().getSerialNumber());
            crlInfoData.setThisUpdate(crlInfo.getThisUpdate());
            crlInfoData.setNextUpdate(crlInfo.getNextUpdate());
            crlInfoData.setCertificateData(certificateData);
            crlInfoData.setStatus(crlInfo.getStatus());
            if (crlData != null) {
                crlInfoData.setCrl(crlData);
            } else {
                crlData = new CRLData();
                crlData.setCrl(crlInfo.getCrl().getX509CRLHolder().getCrlBytes());
                crlInfoData.setCrl(crlData);
            }
            crlInfoData.setPublishedToCDPS(crlInfo.isPublishedToCDPS());
        } catch (final PersistenceException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE + " while retreving CRL status", exception.getMessage());
            throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE + " while retreving CRL status", exception);
        }
        return crlInfoData;
    }

    /**
     * Convert CRLData entity Object to CRL Object Model.
     *
     * @param cRLInfoData
     *            The CRL Data entity object.
     *
     * @return CRL object model.
     * @throws InvalidCertificateException
     *             Thrown when Invalid certificate is found for entity.
     * @throws CRLServiceException
     *             Thrown, if any database failures occurs in case of CRL operations.
     */
    public CRLInfo toAPIFromModel(final CRLInfoData cRLInfoData) throws CRLServiceException, InvalidCertificateException {

        final CRLInfo cRLInfo = new CRLInfo();
        final CertificateData certificateData = cRLInfoData.getCertificateData();
        Certificate certificate = null;
        try {
            certificate = modelMapper.mapToCertificate(certificateData);
        } catch (final CertificateException e1) {
            logger.debug(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION, e1);
            throw new InvalidCertificateException(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION);
        }

        final CRLNumber crlNumber = new CRLNumber();
        crlNumber.setSerialNumber(cRLInfoData.getCrlNumber());

        cRLInfo.setId(cRLInfoData.getId());
        cRLInfo.setCrlNumber(crlNumber);
        cRLInfo.setThisUpdate(cRLInfoData.getThisUpdate());
        cRLInfo.setNextUpdate(cRLInfoData.getNextUpdate());
        cRLInfo.setIssuerCertificate(certificate);
        cRLInfo.setStatus(CRLStatus.fromValue(cRLInfoData.getStatus().toString()));
        cRLInfo.setPublishedToCDPS(cRLInfoData.isPublishedToCDPS());
        if (cRLInfoData.getCrl() != null) {
            try {
                final CRL crl = new CRL();
                crl.setId(cRLInfoData.getId());
                crl.setX509CRLHolder(new X509CRLHolder(cRLInfoData.getCrl().getCrl()));
                cRLInfo.setCrl(crl);
            } catch (CRLException | IOException e) {
                logger.debug("Exception occured while preparing CRL ", e);
                throw new CRLServiceException("Exception occured while preparing CRL");
            }
        }
        return cRLInfo;
    }

}
