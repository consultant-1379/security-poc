/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.model;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.TDPSUrlInfoSetUpData;

/**
 * This class is used to run Junits for TDPSUrlInfo objects in different scenarios
 */
public class TDPSUrlInfoTest extends EqualsTestCase{

    @Override
    protected Object createInstance() throws Exception {
        return new TDPSUrlInfoSetUpData().getTDPSUrlInfoForEqual();
    }

    @Override
    protected Object createNotEqualInstance() throws Exception {
        return new TDPSUrlInfoSetUpData().getTDPSUrlInfoForNotEqual();
    }

}
