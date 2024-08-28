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
package com.ericsson.oss.itpf.security.pki.manager.model;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.TrustCAChainSetupData;

/**
 * This class is used to run Junits for Trust CA Chain objects in different scenarios
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustCAChainTest extends EqualsTestCase {
    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected Object createInstance() throws DatatypeConfigurationException {
        return new TrustCAChainSetupData().getTrustCAChainForEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() throws DatatypeConfigurationException {
        return new TrustCAChainSetupData().getTrustCAChainForNotEqual();
    }
}