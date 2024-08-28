package com.ericsson.oss.itpf.security.pki.manager.validation.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

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

@RunWith(MockitoJUnitRunner.class)
public class ValidationServiceManagerTest {

    @InjectMocks
    ValidationServiceManager validationServiceManager;

    @Test
    public void testTrustProfileValidationServiceInstance() {

        validationServiceManager.getTrustProfileValidationService();
    }

    @Test
    public void testEntityProfileValidationServiceInstance() {

        validationServiceManager.getEntityProfileValidationService();
    }

    @Test
    public void testCertificateProfileValidationServiceInstance() {

        validationServiceManager.getCertificateProfileValidationService();
    }

    @Test
    public void testCaEntityValidationServiceInstance() {

        validationServiceManager.getCaEntityValidationService();
    }

    @Test
    public void testEntityValidationServiceInstance() {

        validationServiceManager.getEntityValidationService();
    }

    @Test
    public void testCertificateValidationInstance() {

        validationServiceManager.getX509CertificateValidationService();
    }

}
