/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl.CmpCertificatesLocalServiceBean;

@RunWith(MockitoJUnitRunner.class)
public class CmpCertificatesLocalServiceBeanTest {

    @InjectMocks
    CmpCertificatesLocalServiceBean cmpCertificatesLocalServiceBean;

    @Mock
    Logger logger;

    @Mock
    InitialConfiguration initialConfiguration;

    @Test
    public void testInitializeVendorCertificates() {
        cmpCertificatesLocalServiceBean.initializeVendorCertificates();
        Mockito.verify(logger).info("Successfully updated Vendor Certificates for the file ");
    }

    @Test
    public void testinitializeCaCertificates() {
        cmpCertificatesLocalServiceBean.initializeCaCertificates();
        Mockito.verify(logger).info("Successfully updated CA Certificates for the file ");
    }
}
