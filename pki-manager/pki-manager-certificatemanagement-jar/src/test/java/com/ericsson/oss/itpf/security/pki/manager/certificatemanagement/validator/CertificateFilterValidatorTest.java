package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

@RunWith(MockitoJUnitRunner.class)
public class CertificateFilterValidatorTest {

    @InjectMocks
    CertificateFilterValidator certificateFilterValidator;

    @Mock
    Logger logger;

    @Test(expected = CertificateException.class)
    public void testValidateCertificateFilter_LimitOffsetZero() throws Exception {

        final CertificateFilter certificateFilter = new CertificateFilter();
        certificateFilter.setLimit(0);
        certificateFilter.setOffset(0);

        certificateFilterValidator.validateCertificateFilter(certificateFilter);

    }

    @Test(expected = CertificateException.class)
    public void testValidateCertificateFilter_LimitNull() throws Exception {

        final CertificateFilter certificateFilter = new CertificateFilter();
        certificateFilter.setLimit(null);

        certificateFilterValidator.validateCertificateFilter(certificateFilter);

    }

    @Test(expected = CertificateException.class)
    public void testValidateCertificateFilter_OffsetNull() throws Exception {

        final CertificateFilter certificateFilter = new CertificateFilter();
        certificateFilter.setOffset(null);

        certificateFilterValidator.validateCertificateFilter(certificateFilter);

    }

}
