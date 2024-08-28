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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPoint;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;

/**
 * This class acts as builder for {@link CRLDistributionPointSetUpData}
 */
public class CRLDistributionPointSetUpData {

    private static final String EQUAL_CRL_ISSUER_NAME = "CA Entity";
    private static final String NOT_EQUAL_CRL_ISSUER_NAME = "Entity";

    /**
     * Method that returns valid CRLDistributionPoint
     * 
     * @return CRLDistributionPoint
     */
    public DistributionPoint getCRLDistributionPointForEqual() {
        final DistributionPoint crlDistributionPoint = new DistributionPoint();
        crlDistributionPoint.setCRLIssuer(EQUAL_CRL_ISSUER_NAME);
        crlDistributionPoint.setDistributionPointName(new DistributionPointNameSetUpData().getDistributionPointNameForEqual());
        crlDistributionPoint.setReasonFlag(ReasonFlag.AA_COMPROMISE);
        crlDistributionPoint.setReasonFlag(ReasonFlag.AFFILIATION_CHANGED);
        crlDistributionPoint.setReasonFlag(ReasonFlag.CA_COMPROMISE);
        return crlDistributionPoint;

    }

    /**
     * Method that returns different valid CRLDistributionPoint
     * 
     * @return CRLDistributionPoint
     */
    public DistributionPoint getCRLDistributionPointForNotEqual() {
        final DistributionPoint crlDistributionPoint = new DistributionPoint();
        crlDistributionPoint.setCRLIssuer(NOT_EQUAL_CRL_ISSUER_NAME);
        crlDistributionPoint.setDistributionPointName(new DistributionPointNameSetUpData().getDistributionPointNameForNotEqual());
        crlDistributionPoint.setReasonFlag(ReasonFlag.SUPERSEDED);
        crlDistributionPoint.setReasonFlag(ReasonFlag.UNUSED);
        crlDistributionPoint.setReasonFlag(ReasonFlag.KEY_COMPROMISE);
        return crlDistributionPoint;

    }
}
