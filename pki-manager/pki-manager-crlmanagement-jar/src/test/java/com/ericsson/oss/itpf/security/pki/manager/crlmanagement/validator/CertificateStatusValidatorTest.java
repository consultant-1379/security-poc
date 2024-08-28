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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.validator;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateStatusValidatorTest {

    @InjectMocks
    CertificateStatusValidator certificateStatusValidator;
    @Mock
    Logger logger;
    private CertificateStatus[] certificateStatuses;

    @Test(expected = ExpiredCertificateException.class)
    public void testValidate_CertificateStatusExpired() {

        certificateStatuses = new CertificateStatus[] { CertificateStatus.EXPIRED };
        certificateStatusValidator.validate(certificateStatuses);
    }

    @Test(expected = RevokedCertificateException.class)
    public void testValidate_CertificateStatusRevoked() {

        certificateStatuses = new CertificateStatus[] { CertificateStatus.REVOKED };
        certificateStatusValidator.validate(certificateStatuses);
    }
}
