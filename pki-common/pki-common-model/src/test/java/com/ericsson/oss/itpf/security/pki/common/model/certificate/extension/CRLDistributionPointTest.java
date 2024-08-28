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
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CRLDistributionPointSetUpData;

/**
 * This class is used to run Junits for CRLDistributionPoint objects in different scenarios
 */
public class CRLDistributionPointTest extends EqualsTestCase {

    CRLDistributionPointSetUpData crlDistributionPointSetUpData = new CRLDistributionPointSetUpData();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    public Object createInstance() {
        return crlDistributionPointSetUpData.getCRLDistributionPointForEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    public Object createNotEqualInstance() {
        return crlDistributionPointSetUpData.getCRLDistributionPointNotForEqual();
    }

}
