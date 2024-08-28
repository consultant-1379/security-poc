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
package com.ericsson.oss.itpf.security.credmservice.api.rest.model;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.test.util.EqualsAndHashTester;
import com.ericsson.oss.itpf.security.credmservice.test.util.JavaBeanTester;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;

public class RestModelTest {

    @Test
    public void beanTest() throws OperatorCreationException {
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new GetCertificateRequest());

        final CredentialManagerAlgorithm algorithm = new CredentialManagerAlgorithm();
        algorithm.setKeySize(2048);
        algorithm.setName("SHA256WITHRSA");
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("localhost");
        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", algorithm.getKeySize());
        final JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subject.retrieveSubjectDN()), keyPair.getPublic());
        final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(algorithm.getName());
        final ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        int getResponseSizeFake = 3;
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new GetCertificateRequest(csr));

        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new GetCertificateResponse(getResponseSizeFake));
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new GetTrustResponse());
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new CreateAndGetEndEntityRequest());

        Map<String, CredentialManagerCertificateAuthority> intTrusts = new HashMap<String, CredentialManagerCertificateAuthority>();
        Map<String, CredentialManagerCertificateAuthority> extTrusts = new HashMap<String, CredentialManagerCertificateAuthority>();
        intTrusts.put("CN=issuer", new CredentialManagerCertificateAuthority("CN=issuer"));
        extTrusts.put("CN=issuerExt", new CredentialManagerCertificateAuthority("CN=issuerExt"));
        CredentialManagerTrustMaps trustMaps = new CredentialManagerTrustMaps();
        trustMaps.setInternalCATrustMap(intTrusts);
        trustMaps.setExternalCATrustMap(extTrusts);
        JavaBeanTester.assertBasicGetterSetterAndToStringBehavior(new GetTrustResponse(trustMaps));
    }

    @Test
    public void equalsTest() throws OperatorCreationException {
        EqualsAndHashTester.testEqualsAndHash(GetCertificateRequest.class);
        GetCertificateRequest certReq1 = new GetCertificateRequest();
        GetCertificateRequest certReq3 = new GetCertificateRequest();
        final CredentialManagerAlgorithm algorithm = new CredentialManagerAlgorithm();
        algorithm.setKeySize(2048);
        algorithm.setName("SHA256WITHRSA");
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setCommonName("localhost");
        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", algorithm.getKeySize());
        final JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subject.retrieveSubjectDN()), keyPair.getPublic());
        final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(algorithm.getName());
        final ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);
        GetCertificateRequest certReq2 = new GetCertificateRequest(csr);
        certReq2.setPassword("password");
        Assert.assertTrue(certReq1.hashCode() != certReq2.hashCode());
        Assert.assertTrue(certReq1.equals(certReq1));
        Assert.assertTrue(!certReq1.equals(null));
        Assert.assertTrue(!certReq1.equals("string"));
        Assert.assertTrue(certReq1.equals(certReq3));
        Assert.assertTrue(!certReq1.equals(certReq2));
        certReq1.setCsrEncoded(certReq2.getCsrEncoded());
        Assert.assertTrue(!certReq1.equals(certReq2));
        certReq1.setPassword(certReq2.getPassword());
        Assert.assertTrue(certReq1.equals(certReq2));

        EqualsAndHashTester.testEqualsAndHash(CreateAndGetEndEntityRequest.class);
        CreateAndGetEndEntityRequest entReq1 = new CreateAndGetEndEntityRequest("entReq", "pass");
        CreateAndGetEndEntityRequest entReq2 = new CreateAndGetEndEntityRequest();
        CreateAndGetEndEntityRequest entReq3 = new CreateAndGetEndEntityRequest();
        Assert.assertTrue(entReq1.hashCode() != entReq2.hashCode());
        Assert.assertTrue(entReq1.equals(entReq1));
        Assert.assertTrue(!entReq1.equals(null));
        Assert.assertTrue(!entReq1.equals("string"));
        Assert.assertTrue(entReq2.equals(entReq3));
        Assert.assertTrue(!entReq2.equals(entReq1));
        entReq2.setHostname(entReq1.getHostname());
        Assert.assertTrue(!entReq2.equals(entReq1));
        entReq2.setPassword(entReq1.getPassword());
        Assert.assertTrue(entReq2.equals(entReq1));

    }
}
