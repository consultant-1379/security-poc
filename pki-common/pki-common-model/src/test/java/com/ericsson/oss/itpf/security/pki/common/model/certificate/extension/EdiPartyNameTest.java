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
package com.ericsson.oss.itpf.security.pki.common.model.certificate.extension;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.EdiPartyNameSetUpData;

/**
 * This class is used to run Junits for EdiPartyName objects in different scenarios
 */
public class EdiPartyNameTest extends EqualsTestCase {

    private static final String EQUAL_ASSIGNER_NAME = "Test_Assigner";
    private static final String NOT_EQUAL_ASSIGNER_NAME = "Test_Assigner_NotEqual";
    private static final String EQUAL_PARTY_NAME = "Test_Party";
    private static final String NOT_EQUAL_PARTY_NAME = "Test_Party_NotEqual";

    EdiPartyNameSetUpData ediPartyNameSetUpData = new EdiPartyNameSetUpData();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance ()
     */
    @Override
    protected Object createInstance() {
        return ediPartyNameSetUpData.getEdiPartyName(EQUAL_ASSIGNER_NAME, EQUAL_PARTY_NAME);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase# createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() {
        return ediPartyNameSetUpData.getEdiPartyName(NOT_EQUAL_ASSIGNER_NAME, NOT_EQUAL_PARTY_NAME);
    }
}