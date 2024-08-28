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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * Converts CRL api model to CRLData jpa model.
 *
 */
public class CRLInfoMapper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateModelMapper certificateModelMapper;

    /**
     * Convert CRL Object model to CRLData entity object.
     *
     * @param crlInfo
     *            The CRL object.
     * @param operationType
     *            The type of Operation to be performed.
     * @return CRLInfoData object.
     * @throws CRLServiceException
     *             Thrown to indicate internal database errors in CRL operations.
     */
    public CRLInfoData fromAPIToModel(final CRLInfo crlInfo, final OperationType operationType) throws  CRLServiceException {
        final CRLInfoData crlInfoData = new CRLInfoData();
        CertificateData certificateData = null;
        try {
            certificateData = persistenceManager.findEntity(CertificateData.class, crlInfo.getIssuerCertificate().getId());
        } catch (final PersistenceException exception) {
            logger.error("Error occured while fetching certificate" + exception.getMessage());
            throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_GETTING_ISSUER_CERTIFICATE, exception);
        }
        CRLData crlData = null;
        if (operationType.equals(OperationType.UPDATE)) {
            crlInfoData.setId(crlInfo.getId());
            try {
                crlData = persistenceManager.findEntity(CRLData.class, crlInfo.getCrl().getId());
            } catch (final PersistenceException exception) {
                logger.error("Error occured while fetching CRL data" + exception.getMessage());
                throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR, exception);
            }
        } else if (operationType.equals(OperationType.CREATE)) {
            crlData = new CRLData();
        } else {
            throw new CRLServiceException("Invalid Operation Type.");
        }
        crlInfoData.setCrlnumber(crlInfo.getCrlNumber().getSerialNumber());
        crlInfoData.setNextUpdate(crlInfo.getNextUpdate());
        crlInfoData.setThisUpdate(crlInfo.getThisUpdate());
        crlInfoData.setStatus(crlInfo.getStatus().getId());
        if (certificateData != null) {
            crlInfoData.setCertificateData(certificateData);
        }
        crlData.setCrl(crlInfo.getCrl().getX509CRLHolder().getCrlBytes());
        crlInfoData.setCrl(crlData);
        crlInfoData.setPublishedTocdps(crlInfo.isPublishedToCDPS());
        return crlInfoData;
    }

    /**
     * Convert CRLData entity Object to Crl Object Model.
     *
     * @param cRLInfoData
     *            The CRL Data entity object.
     * @return CRLInfo object model.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public CRLInfo toAPIFromModel(final CRLInfoData cRLInfoData) throws InvalidCRLGenerationInfoException {
        final CRLInfo crlInfo = new CRLInfo();
        try {
            crlInfo.setId(cRLInfoData.getId());
            crlInfo.setNextUpdate(cRLInfoData.getNextUpdate());
            crlInfo.setThisUpdate(cRLInfoData.getThisUpdate());
            crlInfo.setStatus(CRLStatus.getStatus(cRLInfoData.getStatus()));
            crlInfo.setIssuerCertificate(toCertificate(cRLInfoData.getCertificateData()));
            final CRLNumber crlNumber = new CRLNumber();
            crlNumber.setSerialNumber(cRLInfoData.getCrlnumber());
            crlInfo.setCrlNumber(crlNumber);
            crlInfo.setPublishedToCDPS(cRLInfoData.isPublishedTocdps());
            if (cRLInfoData.getCrl() != null) {
                try {
                    final CRL crl = new CRL();
                    crl.setId(cRLInfoData.getCrl().getId());
                    crl.setX509CRLHolder(new X509CRLHolder(cRLInfoData.getCrl().getCrl()));
                    crlInfo.setCrl(crl);
                } catch (final IOException | java.security.cert.CRLException e) {
                    throw new InvalidCRLGenerationInfoException("Exception occured while preparing CRL ", e);
                }
            }
        } catch (final IOException | CertificateException exception) {
            throw new InvalidCRLGenerationInfoException("Problem with CRL/Certificate Converter" + exception);
        }
        return crlInfo;
    }

    private Certificate toCertificate(final CertificateData certificateData) throws CertificateException, IOException {
        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());
        certificate.setIssuedTime(certificateData.getIssuedTime());
        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateData.getCertificate());
        final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME).getCertificate(certificateHolder);
        certificate.setX509Certificate(x509Certificate);
        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));

        if (certificateData.getIssuerCertificate() != null) {
            certificate.setIssuerCertificate(toCertificate(certificateData.getIssuerCertificate()));
        }

        return certificate;
    }

    /**
     * This method will Convert CRLData entity list to Crl Object Model list
     *
     * @param crlInfoDataList
     *            List of crlInfoData Objects
     * @return - CRL info list
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CRLInfo> toAPIFromModel(final List<CRLInfoData> crlInfoDataList) throws InvalidCRLGenerationInfoException {
        final List<CRLInfo> crlInfoList = new ArrayList<CRLInfo>();
        for (final CRLInfoData crlInfodata : crlInfoDataList) {
            crlInfoList.add(toAPIFromModel(crlInfodata));
        }
        return crlInfoList;
    }
}
