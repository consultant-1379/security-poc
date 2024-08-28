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

import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CommonConstants;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.SubjectAltNameStringSetUpData;

/**
 * This class is used to run Junits for SubjectAltNameString objects in different scenarios
 */
@RunWith(MockitoJUnitRunner.class)
public class SubjectAltNameStringTest extends EqualsTestCase {

    SubjectAltNameStringSetUpData subjectAltNameStringSetUp = new SubjectAltNameStringSetUpData();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance ()
     */
    @Override
    protected Object createInstance() {
        return subjectAltNameStringSetUp.getSubjectAltNameString(CommonConstants.TEST_VALUE);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase# createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() {
        return subjectAltNameStringSetUp.getSubjectAltNameString(CommonConstants.TEST_VALUE_NOT);
    }
}
