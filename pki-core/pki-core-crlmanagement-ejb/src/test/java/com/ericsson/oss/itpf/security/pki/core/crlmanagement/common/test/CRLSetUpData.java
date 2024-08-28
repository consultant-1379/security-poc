/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;

public class CRLSetUpData {

    private static Date notAfterDate = null;
    private static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd/MM/yyyy");
    private static Certificate issuerCertificate;
    private static Date thisUpdate;
    private final static long id = 1033232325;
    private static Date nextUpdate;
    private final static String cerficateSerialNumber = "1508f262d31";
    private final static Integer serialNumber = 10101;
    private final static String source = "31/12/9999";
    private final static CRLInfo crl = new CRLInfo();
    private final static CRLNumber crlNumber = new CRLNumber();
    private final static String statusCheck = "LATEST";

    private CRLSetUpData() {

    }

    /**
     * Method to get values to CRLInfo.
     * 
     * @return CRLInfo
     */
    public static CRLInfo getCRLInfo(final String status) {

        crlNumber.setSerialNumber(serialNumber);

        issuerCertificate = new Certificate();

        issuerCertificate.setStatus(CertificateStatus.ACTIVE);
        issuerCertificate.setSerialNumber(cerficateSerialNumber);
        issuerCertificate.setId(id);
        issuerCertificate.setNotAfter(prepareDate());
        crl.setCrlNumber(crlNumber);
        crl.setId(id);
        crl.setIssuerCertificate(issuerCertificate);
        crl.setNextUpdate(nextUpdate);
        if (status.equals(statusCheck)) {
            crl.setStatus(CRLStatus.LATEST);
        } else {
            crl.setStatus(CRLStatus.INVALID);
        }
        crl.setThisUpdate(thisUpdate);
        return crl;
    }

    private static Date prepareDate() {

        try {
            notAfterDate = simpleDateFormat.parse(source);
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return notAfterDate;
    }

}
