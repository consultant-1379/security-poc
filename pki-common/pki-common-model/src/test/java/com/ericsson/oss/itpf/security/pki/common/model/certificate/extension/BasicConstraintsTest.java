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
import com.ericsson.oss.itpf.security.pki.manager.test.setup.BasicConstraintsSetUpData;

/**
 * This class is used to run Junits for BasicConstraints objects in different scenarios
 */
public class BasicConstraintsTest extends EqualsTestCase {

    private static final int EQUAL_PATH_LENGTH = 10;
    private static final int NOT_EQUAL_PATH_LENGTH = 11;

    BasicConstraintsSetUpData basicConstraintsSetUpData = new BasicConstraintsSetUpData();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance ()
     */
    @Override
    public Object createInstance() {
        return basicConstraintsSetUpData.getBasicConstraints(true, true, true, EQUAL_PATH_LENGTH);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase# createNotEqualInstance()
     */
    @Override
    public Object createNotEqualInstance() {
        return basicConstraintsSetUpData.getBasicConstraints(false, false, false, NOT_EQUAL_PATH_LENGTH);
    }
}
