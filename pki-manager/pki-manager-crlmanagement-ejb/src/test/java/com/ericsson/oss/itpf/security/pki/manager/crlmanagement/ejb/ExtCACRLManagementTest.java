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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.ExtCACRLManager;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACRLManagementTest {

    @Mock
    ExtCACRLManager extCACRLManager;

    @InjectMocks
    ExtCACRLManagement extCACRLManagement;

    @Test
    public void test() {
        Mockito.doNothing().when(extCACRLManager).autoUpdateExpiredCRLs();
        extCACRLManagement.autoUpdateExpiredCRLs();
    }

}
