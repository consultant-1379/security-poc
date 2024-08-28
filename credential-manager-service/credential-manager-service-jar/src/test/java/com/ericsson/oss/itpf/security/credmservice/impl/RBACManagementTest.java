/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.context.ContextService;


@RunWith(MockitoJUnitRunner.class)
public class RBACManagementTest {
   @Mock
    ContextService ctxService;
    @Test
    public void testNegativeWithNull() {
        boolean ret = RBACManagement.injectUserName(null);
        Assert.assertFalse(ret);
    }

    @Test
    public void testPositive() {
        boolean ret = RBACManagement.injectUserName(ctxService);
        Assert.assertTrue(ret);
    }
}
