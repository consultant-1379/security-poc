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
package com.ericsson.itpf.security.pki.cmdhandler.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

@RunWith(MockitoJUnitRunner.class)
public class CertificateUtilsTest {

    @InjectMocks
    CertificateUtils certificateUtils;

    @Mock
    KeyUtil keyUtil;

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    private List<Certificate> certificates;

    @Before
    public void setUp() {
        certificates = new ArrayList<Certificate>();
    }

    @Test
    public void testCreateFileResource() {
        certificateUtils.createFileResource(Constants.EMPTY_STRING.getBytes(), Constants.EMPTY_STRING, ".cer");
    }

    @Ignore
    @Test
    public void testCreatePEMCertificate() throws IOException {

        certificateUtils.createPEMCertificate(certificates, "pemFile");
    }

    @Test
    public void testGetContentType() {
        certificateUtils.getContentType("ERBS_1.jks");
    }

    @Test
    public void testConvertCertificatestoJKS() throws Exception {
        certificateUtils.convertCertificates(certificates, "JKS", "FileName", "secure");
    }

    @Test
    public void testConvertCertificatestoP12() throws Exception {
        certificateUtils.convertCertificates(certificates, "P12", "FileName", "secure");
    }

    @Ignore
    @Test
    public void testConvertCertificatestoPEM() throws Exception {
        certificateUtils.convertCertificates(certificates, "PEM", "FileName", Constants.EMPTY_STRING);
    }

    @Test(expected = CommandSyntaxException.class)
    public void testConvertCertificatestoPEMException() throws Exception {
        certificateUtils.convertCertificates(certificates, "PEM", "FileName", "secure");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConvertCertificatesException() throws Exception {
        certificateUtils.convertCertificates(certificates, Constants.EMPTY_STRING, "FileName", Constants.EMPTY_STRING);
    }
}
