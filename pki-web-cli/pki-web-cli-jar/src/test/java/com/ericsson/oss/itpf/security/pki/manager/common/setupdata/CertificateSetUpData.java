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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;

/**
 * This class acts as builder for {@link CertificateSetUpData}
 */
public class CertificateSetUpData {

    private static final String EQUAL_SERIAL_NUMBER = "123";
    private static final String NOT_EQUAL_SERIAL_NUMBER = "456";
    private static final String EQUAL_ISSUED_TIME = "10-20-2020";
    private static final String NOT_EQUAL_ISSUED_TIME = "10-10-2030";
    private static final String EQUAL_AFTER_TIME = "01-01-2025";
    private static final String NOT_EQUAL_AFTER_TIME = "01-01-2020";
    private static final String EQUAL_BEFORE_TIME = "02-02-2020";
    private static final String NOT_EQUAL_BEFORE_TIME = "02-02-2021";

    /**
     * Method that returns valid Certificate
     * 
     * @return Certificate
     */
    public Certificate getCertificateForEqual() throws ParseException {
        final Certificate certificate = new Certificate();
        certificate.setIssuedTime((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(EQUAL_ISSUED_TIME));
        certificate.setNotAfter((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(EQUAL_AFTER_TIME));
        certificate.setNotBefore((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(EQUAL_BEFORE_TIME));
        certificate.setSerialNumber(EQUAL_SERIAL_NUMBER);
        certificate.setStatus(CertificateStatus.ACTIVE);
        return certificate;
    }

    /**
     * Method that returns different valid Certificate
     * 
     * @return Certificate
     */
    public Certificate getCertificateForNotEqual() throws ParseException {
        final Certificate certificate = new Certificate();
        certificate.setIssuedTime((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(NOT_EQUAL_ISSUED_TIME));
        certificate.setNotAfter((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(NOT_EQUAL_AFTER_TIME));
        certificate.setNotBefore((new SimpleDateFormat(CommonConstants.DATE_FORMAT)).parse(NOT_EQUAL_BEFORE_TIME));
        certificate.setSerialNumber(NOT_EQUAL_SERIAL_NUMBER);
        certificate.setStatus(CertificateStatus.EXPIRED);
        return certificate;
    }
}
