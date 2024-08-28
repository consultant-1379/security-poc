/*------------------------------------------------------------------------------
 ********************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 ********************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import java.io.*;
import java.security.cert.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentInfo;

public class EnrollmentInfoSetUpData {

    private static final String EQUAL_ENROLLMENT_URL = "EqualEnrollmentURL";
    private static final String NOT_EQUAL_ENROLLMENT_URL = "NotEqualEnrollmentURL";
    private static final String EQUAL_DISTRIBUTION_URL = "EqualTrustDistributionURL";
    private static final String NOT_EQUAL_DISTRIBUTION_URL = "NotEqualTrustDistributionURL";

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Method that returns valid EnrollmentInfo
     * 
     * @return EnrollmentInfo
     */
    public EnrollmentInfo getEnrollmentInfoForEqual() {
        InputStream inStream = null;
        CertificateFactory cf = null;
        X509Certificate certificate = null;
        try {
            inStream = new FileInputStream("src/test/resources/MyRoot.crt");
            cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(inStream);
        } catch (FileNotFoundException e) {
            logger.error("The given file not found in the EnrollmentInfoSetUpData class");
        } catch (CertificateException e) {
            logger.error("Certificate Exception found in EnrollmentInfoSetUpData class");
        }

        final EnrollmentInfo enrollmentInfo = new EnrollmentInfo();
        enrollmentInfo.setCaCertificate(certificate);
        enrollmentInfo.setEnrollmentURL(EQUAL_ENROLLMENT_URL);
        enrollmentInfo.setTrustDistributionPointURL(EQUAL_DISTRIBUTION_URL);
        return enrollmentInfo;
    }

    /**
     * Method that returns different valid EnrollmentInfo
     * 
     * @return EnrollmentInfo
     */
    public EnrollmentInfo getEnrollmentInfoForNotEqual() {
        final EnrollmentInfo enrollmentInfo = new EnrollmentInfo();
        enrollmentInfo.setEnrollmentURL(NOT_EQUAL_ENROLLMENT_URL);
        enrollmentInfo.setTrustDistributionPointURL(NOT_EQUAL_DISTRIBUTION_URL);
        return enrollmentInfo;
    }
}
