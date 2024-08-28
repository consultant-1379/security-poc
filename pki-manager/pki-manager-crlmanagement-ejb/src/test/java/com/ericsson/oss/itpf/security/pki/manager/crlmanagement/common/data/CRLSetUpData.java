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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data;

/**
 *  This class is used to prepare initial set up data for CRLManagement Service .
 */
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;

public class CRLSetUpData {

    private static final Integer cRLSerialNumber = 123456;
    private static final String caName = "ENM_RootCA";
    private static final String cerficateSerialNumber = "1508f262d31";
    private static SimpleDateFormat sd = new SimpleDateFormat("dd/MM/yyyy");
    private static final String notAfterDate = "31/12/9999";

    /**
     * Method to get values to CRLInfo.
     * 
     * @return CRLInfo
     */
    public static CRLInfo getCRLInfo() {
        final CRLInfo cRLInfo = new CRLInfo();
        CRLNumber cRLNumber = new CRLNumber();
        cRLNumber.setSerialNumber(cRLSerialNumber);
        cRLInfo.setCrlNumber(cRLNumber);
        cRLInfo.setIssuerCertificate(getIssuerCertificate());
        cRLInfo.setNextUpdate(new Date());
        cRLInfo.setStatus(CRLStatus.LATEST);
        cRLInfo.setThisUpdate(new Date());
        return cRLInfo;
    }

    /**
     * Method to get CACertificateIdentifier.
     * 
     * @return CACertificateIdentifier.
     */

    public static CACertificateIdentifier getCACertificateIdentifier() {
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName(caName);
        caCertificateIdentifier.setCerficateSerialNumber(cerficateSerialNumber);
        return caCertificateIdentifier;
    }

    /**
     * Method to get getIssuerCertificate.
     * 
     * @return Certificate.
     */
    private static Certificate getIssuerCertificate() {
        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setSerialNumber(cerficateSerialNumber);
        issuerCertificate.setStatus(CertificateStatus.ACTIVE);
        issuerCertificate.setNotAfter(getNotAfterDate());
        return issuerCertificate;
    }

    /**
     * Method to get NotAfterDate
     * 
     * @return Date
     */
    private static Date getNotAfterDate() {
        Date date = null;
        try {
            date = sd.parse(notAfterDate);
        } catch (ParseException parseException) {
            parseException.getMessage();
        }
        return date;
    }

}
