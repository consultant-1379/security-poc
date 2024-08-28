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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;

/**
 * This class acts as builder for {@link CertificateAuthoritySetUpData}
 */
public class BasicConstraintsSetUpData {
    /**
     * Method that returns valid BasicConstraints
     * 
     * @return BasicConstraints
     */
    public BasicConstraints getBasicConstraints(final boolean critical, final boolean enabled, final boolean isCA, final int pathLength) {
        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setCritical(critical);
        basicConstraints.setIsCA(isCA);
        basicConstraints.setPathLenConstraint(pathLength);
        return basicConstraints;
    }
}
