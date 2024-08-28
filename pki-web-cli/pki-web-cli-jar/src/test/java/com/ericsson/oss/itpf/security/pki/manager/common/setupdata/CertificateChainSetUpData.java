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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * This class acts as builder for {@link CertificateChainSetUpData}
 */

public class CertificateChainSetUpData {

    private static final String EQUAL_SERIAL_NUMBER = "1234";
    private static final String EQUAL_ISSUED_TIME = "11-20-2020";
    private static final String EQUAL_AFTER_TIME = "12-01-2025";
    private static final String EQUAL_BEFORE_TIME = "03-02-2020";

    /**
     * Method that returns valid CertificateChain
     * 
     * @return CertificateChain
     * @throws ParseException
     */
    public CertificateChain getCertificateChainDataForEqual() throws ParseException {

        final CertificateChain certificateChain = new CertificateChain();
        final List<Certificate> certList = new ArrayList<Certificate>();
        certList.add(new CertificateSetUpData().getCertificateForEqual());
        final Certificate certificate = createCertificate();
        certList.add(certificate);
        certificateChain.setCertificateChain(certList);
        return certificateChain;
    }

    /**
     * @return
     * @throws ParseException
     */
    private Certificate createCertificate() throws ParseException {

        final Certificate certificate = new Certificate();
        certificate.setIssuedTime((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(EQUAL_ISSUED_TIME));
        certificate.setNotAfter((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(EQUAL_AFTER_TIME));
        certificate.setNotBefore((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(EQUAL_BEFORE_TIME));
        certificate.setSerialNumber(EQUAL_SERIAL_NUMBER);
        certificate.setStatus(CertificateStatus.ACTIVE);
        return certificate;
    }

    /**
     * Method that returns CertificateChain with empty list
     * 
     * @return CertificateChain
     * 
     */

    public CertificateChain getCertificateChainWithEmptyList() {

        final CertificateChain certificateChain = new CertificateChain();
        final List<Certificate> certList = new ArrayList<Certificate>();
        certificateChain.setCertificateChain(certList);
        return certificateChain;
    }

    /**
     * Method that returns different CertificateChain object
     * 
     * @return CertificateChain
     * @throws ParseException
     */
    public CertificateChain getCertificateChainDataForNotEqual() throws ParseException {

        final CertificateChain certificateChain = new CertificateChain();

        final List<Certificate> certList = new ArrayList<Certificate>();
        certList.add(new CertificateSetUpData().getCertificateForNotEqual());

        final Certificate certificate = new CertificateSetUpData().getCertificateForNotEqual();
        certificate.setStatus(CertificateStatus.REVOKED);
        certificateChain.setCertificateChain(certList);

        return certificateChain;
    }
}
