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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;

/**
 * This class acts as builder for {@link CertificateAuthoritySetUpData}
 */
public class BasicConstraintsSetUpData {

    private static final int EQUAL_PATH_LENGTH = 0;
    private static final int NOT_EQUAL_PATH_LENGTH = 1;

    /**
     * Method that returns valid BasicConstraints
     * 
     * @return BasicConstraints
     */
    public BasicConstraints getBasicConstraintsForEqual() {
        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setCritical(true);
        basicConstraints.setIsCA(true);
        basicConstraints.setPathLenConstraint(EQUAL_PATH_LENGTH);
        return basicConstraints;
    }

    /**
     * Method that returns different valid BasicConstraints
     * 
     * @return BasicConstraints
     */
    public BasicConstraints getBasicConstraintsForNotEqual() {
        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setCritical(false);
        basicConstraints.setIsCA(false);
        basicConstraints.setPathLenConstraint(NOT_EQUAL_PATH_LENGTH);
        return basicConstraints;
    }
}
