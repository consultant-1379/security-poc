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
package com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.impl.TDPSManager;

@RunWith(MockitoJUnitRunner.class)
public class TrustDistributionPointServiceBeanTest {

    @InjectMocks
    TrustDistributionPointServiceBean trustDistributionPointServiceBean;

    @Mock
    TDPSManager tdpsManager;

    @Mock
    TrustDistributionParameters trustDistributionParameters;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void testGetCertificate() {
        trustDistributionPointServiceBean.getCertificate(trustDistributionParameters);
        Mockito.verify(tdpsManager).getCertificate(trustDistributionParameters);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCertificateException() {
        Mockito.when(tdpsManager.getCertificate(trustDistributionParameters)).thenThrow(new CertificateNotFoundException());
        trustDistributionPointServiceBean.getCertificate(trustDistributionParameters);
        CertificateNotFoundException certificateNotFoundException = new CertificateNotFoundException();
        Mockito.verify(logger).debug("Exception StackTrace: ", certificateNotFoundException);
    }

}
