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

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;

/**
 * This class acts as builder for {@link DistributionPointNameSetUpData}
 */
public class DistributionPointNameSetUpData {

    private static final String EQUAL_FULL_NAME1 = "www.google.com";
    private static final String EQUAL_FULL_NAME2 = "www.tcs.com";
    private static final String NOT_EQUAL_FULL_NAME1 = "www.verisign.com";
    private static final String NOT_EQUAL_FULL_NAME2 = "www.ericsson.com";
    private static final String EQUAL_RELATIVE_NAME = "CAEntityIssuer";
    private static final String NOT_EQUAL_RELATIVE_NAME = "www.ericsson.com";

    /**
     * Method that returns valid DistributionPointName
     * 
     * @return DistributionPointName
     */
    public DistributionPointName getDistributionPointNameForEqual() {
        final DistributionPointName distributionPointName = new DistributionPointName();
        final List<String> fullName = new ArrayList<String>();
        fullName.add(EQUAL_FULL_NAME1);
        fullName.add(EQUAL_FULL_NAME2);
        distributionPointName.setFullName(fullName);
        distributionPointName.setNameRelativeToCRLIssuer(EQUAL_RELATIVE_NAME);
        return distributionPointName;

    }

    /**
     * Method that returns different valid DistributionPointName
     * 
     * @return DistributionPointName
     */
    public DistributionPointName getDistributionPointNameForNotEqual() {
        final DistributionPointName distributionPointName = new DistributionPointName();
        final List<String> fullName = new ArrayList<String>();
        fullName.add(NOT_EQUAL_FULL_NAME1);
        fullName.add(NOT_EQUAL_FULL_NAME2);
        distributionPointName.setFullName(fullName);
        distributionPointName.setNameRelativeToCRLIssuer(NOT_EQUAL_RELATIVE_NAME);
        return distributionPointName;

    }

}
