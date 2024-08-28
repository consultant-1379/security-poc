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
/**
 * @author tcsvenp
 *
 */
package com.ericsson.oss.itpf.security.pki.manager.model;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.EnrollmentInfoSetUpData;

/**
 * This class is used to run Junits for EnrollmentInfo objects in different scenarios
 */
public class EnrollmentInfoTest extends EqualsTestCase {

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected Object createInstance() {
        return new EnrollmentInfoSetUpData().getEnrollmentInfoForEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() {
        return new EnrollmentInfoSetUpData().getEnrollmentInfoForNotEqual();
    }

}