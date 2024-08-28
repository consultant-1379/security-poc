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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.Date;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRL;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CRLInfoEventMapper;

@RunWith(MockitoJUnitRunner.class)
public class CRLInfoEventMapperTest {

    @InjectMocks
    CRLInfoEventMapper crlInfoEventMapper;

    private CRLInfo crlInfo;
    private com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo returnCRLInfo;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        crlInfo = new CRLInfo();

        CRL crl = new CRL();
        crl.setId(123456);

        X509CRLHolder x509crlHolder = new X509CRLHolder(getX509CRL("crls/testCA.crl"));
        crl.setX509CRLHolder(x509crlHolder);

        crlInfo.setCrl(crl);

        CRLNumber crlNumber = new CRLNumber();
        crlNumber.setCritical(true);
        crlNumber.setSerialNumber(123456);
        crlInfo.setCrlNumber(crlNumber);

        crlInfo.setId(123456);

        Certificate issuerCertificate = new Certificate();
        issuerCertificate.setId(123456);
        issuerCertificate.setIssuedTime(new Date());

        CertificateAuthority issuer = new CertificateAuthority();
        issuerCertificate.setIssuer(issuer);
        issuerCertificate.setSerialNumber("123456");
        issuerCertificate.setStatus(CertificateStatus.ACTIVE);
        crlInfo.setIssuerCertificate(issuerCertificate);

        crlInfo.setPublishedToCDPS(true);

        crlInfo.setStatus(CRLStatus.LATEST);
    }

    private X509CRL getX509CRL(String fileName) throws FileNotFoundException, CRLException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        return x509crl;
    }

    @Test
    public void fromModel() throws CRLException, FileNotFoundException, CertificateException {
        returnCRLInfo = crlInfoEventMapper.fromModel(crlInfo);
        Assert.assertNotNull(returnCRLInfo.getEncodedCRL());
    }
}