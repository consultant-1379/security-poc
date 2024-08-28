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
import com.ericsson.oss.itpf.security.pki.manager.test.setup.KeyUsageSetUpData;

/**
 * This class is used to run Junits for KeyUsage objects in different scenarios
 */
public class KeyUsageTest extends EqualsTestCase {

    KeyUsageSetUpData keyUsageSetUpData = new KeyUsageSetUpData();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance ()
     */
    @Override
    public Object createInstance() {
        return keyUsageSetUpData.getKeyUsageForEqual(true);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase# createNotEqualInstance()
     */
    @Override
    public Object createNotEqualInstance() {
        return keyUsageSetUpData.getKeyUsageForNotEqual(false);
    }
}