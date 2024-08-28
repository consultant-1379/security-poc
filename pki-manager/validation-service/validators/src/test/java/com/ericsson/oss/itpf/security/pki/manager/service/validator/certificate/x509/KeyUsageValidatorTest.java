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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509;

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc.CertificateBase;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class KeyUsageValidatorTest {

    @InjectMocks
    KeyUsageValidator keyUsageValidator;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    @Mock
    CSRExtensionUtils csrExtensionUtils;

    @Mock
    KeyUsage keyUsage;
    @Mock
    Logger logger;

    CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
    CertificateBase certificateBase = new CertificateBase();
    String caName = "caName";
    X509Certificate x509Certificate = null;

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {

        caCertificateValidationInfo = setupData();

        Mockito.when(certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.keyUsage.getId())).thenReturn(x509Certificate.getEncoded());
        Mockito.when(csrExtensionUtils.getCSRAttributeExtensionValue(caName, Extension.keyUsage)).thenReturn(x509Certificate.getEncoded());
        Mockito.when((KeyUsage) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.KEY_USAGE)).thenReturn(keyUsage);
        final List<KeyUsageType> csrKeyUsageTypes=getKeyUsageTypes();
        Mockito.when(keyUsage.getSupportedKeyUsageTypes()).thenReturn(csrKeyUsageTypes);
        final List<Integer> csrKeyUsageIds=getKeyIds(csrKeyUsageTypes);
        final List<Integer> certificateKeyUsageIds=new ArrayList<Integer>();
        certificateKeyUsageIds.add(KeyUsageType.CRL_SIGN.getId());
        Mockito.when(certificateExtensionUtils.compareCSRandCertificateFields(csrKeyUsageIds, certificateKeyUsageIds)).thenReturn(true);
        keyUsageValidator.validate(caCertificateValidationInfo);
    }
    @Test(expected=MissingMandatoryFieldException.class)
    public void testMissingMandatoryFieldException() throws CertificateException, FileNotFoundException {

        caCertificateValidationInfo = setupData();
        final List<KeyUsageType> csrKeyUsageTypes=getKeyUsageTypes();
        final List<Integer> csrKeyUsageIds=getKeyIds(csrKeyUsageTypes);
        final List<Integer> certificateKeyUsageIds=new ArrayList<Integer>();
        certificateKeyUsageIds.add(KeyUsageType.KEY_CERT_SIGN.getId());
        
        Mockito.when((KeyUsage) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.KEY_USAGE)).thenReturn(keyUsage);
       
        Mockito.when(keyUsage.getSupportedKeyUsageTypes()).thenReturn(csrKeyUsageTypes);
        
        Mockito.when(certificateExtensionUtils.compareCSRandCertificateFields(csrKeyUsageIds, certificateKeyUsageIds)).thenReturn(true);
        keyUsageValidator.validate(caCertificateValidationInfo);
        Mockito.verify(certificateExtensionUtils).getCertificateAttributeExtensionValue(x509Certificate, Extension.keyUsage.getId());
    }

    private CACertificateValidationInfo setupData() throws CertificateException, FileNotFoundException {

        x509Certificate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        caCertificateValidationInfo.setCertificate(x509Certificate);
        caCertificateValidationInfo.setCaName(caName);

        CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setCsr(x509Certificate.getEncoded());

        CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        return caCertificateValidationInfo;
    }
    private List<KeyUsageType> getKeyUsageTypes(){
    final List<KeyUsageType> csrKeyUsageTypes=new ArrayList<KeyUsageType>();
    csrKeyUsageTypes.add(KeyUsageType.CRL_SIGN);
    csrKeyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
    return csrKeyUsageTypes;
}
    private List<Integer> getKeyIds(final List<KeyUsageType> csrKeyUsageTypes){
    	 final List<Integer> csrKeyUsageIds = new ArrayList<Integer>();
         for (final KeyUsageType keyUsageType : csrKeyUsageTypes) {
             csrKeyUsageIds.add(keyUsageType.getId());
         }
         return csrKeyUsageIds;
    }
}
