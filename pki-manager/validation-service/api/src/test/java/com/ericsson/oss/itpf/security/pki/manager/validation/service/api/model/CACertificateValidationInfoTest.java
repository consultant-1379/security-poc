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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model;


import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;

@RunWith(MockitoJUnitRunner.class)
public class CACertificateValidationInfoTest {

    @Mock
    X509Certificate certificate;
    final private String caName = "NEW_CA";
    final private String caName1 = "NEW_CA1";
    final private String caName2 = "NEW_CA2";
    final private String caName4 = "NEW_CA4";
    final private String caName5 = "NEW_CA5";
    final private String caName6 = "NEW_CA6";

    @Test
    public void testSettersGetters(){

        final CertificateAuthority issuer = new CertificateAuthority();
        issuer.setId(1);
        issuer.setName(caName);

        final CACertificateValidationInfo caCertificateValidationInfo = Mockito.mock(CACertificateValidationInfo.class, Mockito.RETURNS_DEEP_STUBS);
        // connect getter and setter
        Mockito.when(caCertificateValidationInfo.getCaName()).thenCallRealMethod();
        Mockito.doCallRealMethod().when(caCertificateValidationInfo).setCaName(Mockito.anyString());

        caCertificateValidationInfo.setCaName(caName);
        Assert.assertEquals(caName, caCertificateValidationInfo.getCaName());

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenCallRealMethod();
        Mockito.doCallRealMethod().when(caCertificateValidationInfo).setCertificate(Mockito.any(X509Certificate.class));

        caCertificateValidationInfo.setCertificate(certificate);
        Assert.assertEquals(certificate, caCertificateValidationInfo.getCertificate());

        Mockito.when(caCertificateValidationInfo.isForceImport()).thenCallRealMethod();
        Mockito.doCallRealMethod().when(caCertificateValidationInfo).setForceImport(Mockito.anyBoolean());

        caCertificateValidationInfo.setForceImport(true);
        Assert.assertEquals(true, caCertificateValidationInfo.isForceImport());
    }

    @Test
    public void testEquals(){

        final CertificateAuthority issuer = new CertificateAuthority();
        issuer.setId(1);
        issuer.setName(caName);

        final CACertificateValidationInfo caCertificateValidationInfo1 = new CACertificateValidationInfo();
        final CACertificateValidationInfo caCertificateValidationInfo2 = new CACertificateValidationInfo();
        caCertificateValidationInfo1.setCaName(caName1);
        caCertificateValidationInfo2.setCaName(caName2);

        Assert.assertTrue(caCertificateValidationInfo1.equals(caCertificateValidationInfo1));

        Assert.assertFalse(caCertificateValidationInfo1.equals(caCertificateValidationInfo2));

        Assert.assertFalse(caCertificateValidationInfo1.equals(null));

        Assert.assertFalse(caCertificateValidationInfo1.equals(new Object()));

        final CACertificateValidationInfo caCertificateValidationInfo3 = new CACertificateValidationInfo();
        final CACertificateValidationInfo caCertificateValidationInfo4 = new CACertificateValidationInfo();
        caCertificateValidationInfo3.setCaName(null);
        caCertificateValidationInfo4.setCaName(caName4);
        caCertificateValidationInfo3.setCertificate(null);
        caCertificateValidationInfo4.setForceImport(true);
        caCertificateValidationInfo3.setForceImport(false);
        Assert.assertFalse(caCertificateValidationInfo3.equals(caCertificateValidationInfo4));

        final CACertificateValidationInfo caCertificateValidationInfo5 = new CACertificateValidationInfo();
        final CACertificateValidationInfo caCertificateValidationInfo6 = new CACertificateValidationInfo();
        caCertificateValidationInfo5.setCaName(caName5);
        caCertificateValidationInfo6.setCaName(caName6);
        caCertificateValidationInfo5.setCertificate(null);
        caCertificateValidationInfo6.setForceImport(true);
        caCertificateValidationInfo5.setForceImport(false);
        Assert.assertFalse(caCertificateValidationInfo5.equals(caCertificateValidationInfo6));
    }

    @Test
    public void testHashCode(){

        final CertificateAuthority issuer = new CertificateAuthority();
        issuer.setId(1);
        issuer.setName(caName);

        final CACertificateValidationInfo caCertificateValidationInfo = Mockito.mock(CACertificateValidationInfo.class, Mockito.RETURNS_DEEP_STUBS);
        final CACertificateValidationInfo caCertificateValidationInfo1 = new CACertificateValidationInfo();
        final CACertificateValidationInfo caCertificateValidationInfo2 = new CACertificateValidationInfo();
        caCertificateValidationInfo1.setCaName(caName1);
        caCertificateValidationInfo2.setCaName(caName2);

        caCertificateValidationInfo1.setCertificate(certificate);
        caCertificateValidationInfo2.setCertificate(certificate);
        caCertificateValidationInfo1.setForceImport(true);
        caCertificateValidationInfo2.setForceImport(false);
        Assert.assertFalse(caCertificateValidationInfo2.equals(caCertificateValidationInfo1));

        Assert.assertFalse(caCertificateValidationInfo.hashCode()==caCertificateValidationInfo1.hashCode());
        
    }
    
    
}
