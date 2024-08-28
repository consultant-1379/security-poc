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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.rest.CertificateManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.CertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementServiceLocalBeanTest {

    @InjectMocks
    CertificateManagementServiceLocalBean certificateManagementServiceLocalBean;

    @Mock
    CertificateManager certificateManager;

    @Mock
    CertificateManagementAuthorizationHandler certificateManagementAuthorizationHandler;

    @Mock
    Logger logger;

    /**
     * This method tests getCertificates method in positive scenario.
     */
    @Test
    public void testGetCertificates() {
        final CertificateFilter certificateFilter = new CertificateFilter();
        final List<Certificate> certificateList = new ArrayList<Certificate>();
        final Certificate certificate = new Certificate();
        certificate.setId(1);
        certificateList.add(certificate);
        Mockito.doNothing().when(certificateManagementAuthorizationHandler).authorizeListCACerts();
        when(certificateManager.getCertificates(certificateFilter)).thenReturn(certificateList);
        final List<Certificate> certificates = certificateManagementServiceLocalBean.getCertificates(certificateFilter);

        Assert.assertNotNull(certificates);
    }

    /**
     * This method tests getCertificateCount method in positive scenario.
     */
    @Test
    public void testGetCertificateCount() {
        final CertificateFilter certificateFilter = new CertificateFilter();
        Mockito.doNothing().when(certificateManagementAuthorizationHandler).authorizeListCACerts();
        when(certificateManager.getCertificateCount(certificateFilter)).thenReturn(new Long(3));
        final long certificatesCount = certificateManagementServiceLocalBean.getCertificateCount(certificateFilter);

        Assert.assertEquals(3, certificatesCount);
    }

}
