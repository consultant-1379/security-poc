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
package com.ericsson.oss.itpf.security.rest.resources;

import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.CredMServiceWeb;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetCertificateRequest;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetCertificateResponse;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

public class CertificateTest {

    @Mock
    CredMService credMService;

    @Mock
    Logger logger;

    @InjectMocks
    Certificate certificate;

    @Mock
    CredMRestAvailability credMPkiConfBean;

    @Mock
    CredMServiceWeb credmServiceWeb;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetCertificate() throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerCertificateEncodingException,
            CredentialManagerEntityNotFoundException, CredentialManagerCertificateGenerationException, CredentialManagerInvalidCSRException,
            CredentialManagerInvalidEntityException, CredentialManagerCertificateExsitsException, CertificateServiceException {

        final CredentialManagerAlgorithm algorithm = new CredentialManagerAlgorithm();
        algorithm.setKeySize(2048);
        algorithm.setName("SHA256WITHRSA");
        // final X509Name x509Name = new X509Name("CN=pippo");
        final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", algorithm.getKeySize());
        PKCS10CertificationRequest csr = null;
        try {

            // getProfile
            final CredentialManagerSubject subject = new CredentialManagerSubject();
            subject.setCommonName("localhost");
            subject.setOrganizationName("Ericsson");
            subject.setOrganizationalUnitName("EricssonOAM");
            final String endEntityProfileName = "credMServiceProfile";
            final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
            keyGenerationAlgorithm.setKeySize(2048);
            keyGenerationAlgorithm.setName("RSA");
            final CredentialManagerProfileInfo profile = new CredentialManagerProfileInfo();
            profile.setSubjectByProfile(subject);
            profile.setKeyPairAlgorithm(keyGenerationAlgorithm);
            profile.setIssuerName("DEFAULT");
            when(credMPkiConfBean.isEnabled()).thenReturn(true);
            when(credMService.getProfile(endEntityProfileName)).thenReturn(profile);

            final JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name(subject.retrieveSubjectDN()), keyPair.getPublic());

            final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(algorithm.getName());

            try {
                final ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
                csr = csrBuilder.build(signer);
            } catch (final OperatorCreationException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();

            }

            final CredentialManagerPKCS10CertRequest credmCSR = new CredentialManagerPKCS10CertRequest(csr);

            final String entityName = "CN=localhost";
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            final Date validityBeginDate = new Date(System.currentTimeMillis() - 24L * 60L * 60L * 1000L);

            final Date validityEndDate = new Date(System.currentTimeMillis() + (365 * 24L * 60L * 60L * 1000L));

            final X500Name issuerName = new X500Name(subject.retrieveSubjectDN());
            final X500Name subjectName = new X500Name(subject.retrieveSubjectDN());

            final X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuerName, BigInteger.valueOf(System.currentTimeMillis()),
                    validityBeginDate, validityEndDate, subjectName, credmCSR.getRequest().getSubjectPublicKeyInfo());

            final PrivateKey caPrivateKey = keyPair.getPrivate();

            // try {
            // addX509Extensionsv2(credmCSR.getRequest(), certGen);
            // } catch (final IOException e1) {
            // // TODO Auto-generated catch block
            // e1.printStackTrace();
            // }
            CredentialManagerX509Certificate[] certResp = null;

            try {
                final ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider("BC").build(caPrivateKey);
                final X509CertificateHolder cert = certGen.build(sigGen);
                final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
                certResp = new CredentialManagerX509Certificate[] { new CredentialManagerX509Certificate(x509Certificate) };
            } catch (final Exception e) {
                throw new CertificateServiceException(e.getMessage());
            }
            when(credMPkiConfBean.isEnabled()).thenReturn(true);
            // now credmAPI certificate is requested with chain
            when(credMService.getCertificate(credmCSR, entityName, true, null)).thenReturn(certResp);

            final GetCertificateRequest certificateRequest = new GetCertificateRequest(csr);
            certificateRequest.setPassword("secret");
            Response resp = certificate.getCertificate(certificateRequest);
            final GetCertificateResponse responseGetCertificate = (GetCertificateResponse) resp.getEntity();

            final CredentialManagerX509Certificate x509certificate = new CredentialManagerX509Certificate(
                    DatatypeConverter.parseBase64Binary(responseGetCertificate.getCertificate()[0]));

            final String certName = x509certificate.retrieveCertificate().getSubjectDN().getName();
            final PublicKey publicKey = x509certificate.retrieveCertificate().getPublicKey();
            Assert.assertEquals(subject.retrieveSubjectDN(), certName);
            Assert.assertEquals(keyPair.getPublic(), publicKey);
            verify(credMService).getCertificate(isA(CredentialManagerPKCS10CertRequest.class), isA(String.class), anyBoolean(), Matchers.anyString());

            //server errors mock
            when(credMService.getCertificate(credmCSR, entityName, true, null)).thenThrow(new CredentialManagerCertificateEncodingException())
                    .thenThrow(new CredentialManagerEntityNotFoundException()).thenThrow(new CredentialManagerCertificateGenerationException())
                    .thenThrow(new CredentialManagerInvalidCSRException()).thenThrow(new CredentialManagerInvalidEntityException())
                    .thenThrow(new CredentialManagerCertificateExsitsException());
            for (int i = 0; i < 6; i++) {
                resp = certificate.getCertificate(certificateRequest);
                Assert.assertEquals(resp.getStatus(), Status.INTERNAL_SERVER_ERROR.getStatusCode());
            }

        } catch (IllegalStateException | IOException | java.security.cert.CertificateException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testWrongGetCertificate() {

        when(credMPkiConfBean.isEnabled()).thenReturn(false);

        final GetCertificateRequest certificateRequest = new GetCertificateRequest();
        final Response resp = certificate.getCertificate(certificateRequest);
        Assert.assertEquals(resp.getStatus(), Status.SERVICE_UNAVAILABLE.getStatusCode());
    }

    @Test
    public void testGetCertificateTest() {

        final Response resp = certificate.getCertificateTest();
        Assert.assertEquals(resp.getStatus(), Status.INTERNAL_SERVER_ERROR.getStatusCode());
    }

    @Test
    public void testReissueSuccess()
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        final List<String> serviceList = new ArrayList<String>();
        serviceList.add("MyService");
        final Set<CredentialManagerEntity> serviceSet = new HashSet<CredentialManagerEntity>();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setEntityType(CredentialManagerEntityType.ENTITY);
        entity.setName("MyService");
        serviceSet.add(entity);
        when(credmServiceWeb.getServices()).thenReturn(serviceSet);
        Mockito.doNothing().when(credmServiceWeb).reissueCertificateByService(Mockito.any(String.class));
        final Response response = certificate.getReissueCertificate(serviceList);
        Assert.assertEquals(Status.OK.getStatusCode(), response.getStatus());
    }

    @Test
    public void testReissueInternalServiceException()
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        final List<String> serviceList = new ArrayList<String>();
        serviceList.add("MyService");
        final Set<CredentialManagerEntity> serviceSet = new HashSet<CredentialManagerEntity>();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setEntityType(CredentialManagerEntityType.ENTITY);
        entity.setName("MyService");
        serviceSet.add(entity);
        when(credmServiceWeb.getServices()).thenReturn(serviceSet);
        Mockito.doThrow(CredentialManagerInternalServiceException.class).when(credmServiceWeb).reissueCertificateByService(Mockito.any(String.class));
        Response response = certificate.getReissueCertificate(serviceList);
        Assert.assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
        Mockito.doThrow(CredentialManagerInternalServiceException.class).when(credmServiceWeb).getServices();
        response = certificate.getReissueCertificate(serviceList);
        Assert.assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testReissueEntityNotFoundException()
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        final List<String> serviceList = new ArrayList<String>();
        serviceList.add("MyService");
        final Set<CredentialManagerEntity> serviceSet = new HashSet<CredentialManagerEntity>();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setEntityType(CredentialManagerEntityType.ENTITY);
        entity.setName("MyService");
        serviceSet.add(entity);
        when(credmServiceWeb.getServices()).thenReturn(serviceSet);
        Mockito.doThrow(CredentialManagerEntityNotFoundException.class).when(credmServiceWeb).reissueCertificateByService(Mockito.any(String.class));
        final Response response = certificate.getReissueCertificate(serviceList);
        Assert.assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testReissueEntityInvalidEntityException()
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        final List<String> serviceList = new ArrayList<String>();
        serviceList.add("MyService");
        final Set<CredentialManagerEntity> serviceSet = new HashSet<CredentialManagerEntity>();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setEntityType(CredentialManagerEntityType.ENTITY);
        entity.setName("MyService");
        serviceSet.add(entity);
        when(credmServiceWeb.getServices()).thenReturn(serviceSet);
        Mockito.doThrow(CredentialManagerInvalidEntityException.class).when(credmServiceWeb).reissueCertificateByService(Mockito.any(String.class));
        final Response response = certificate.getReissueCertificate(serviceList);
        Assert.assertEquals(Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    @Test
    public void testReissueEmptyList() {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        final List<String> serviceList = new ArrayList<String>();

        final Response response = certificate.getReissueCertificate(serviceList);
        Assert.assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @Test
    public void testReissueListNull() {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);

        final Response response = certificate.getReissueCertificate(null);
        Assert.assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @Test
    public void testReissueNoService() throws CredentialManagerInternalServiceException {
        when(credMPkiConfBean.isEnabled()).thenReturn(true);
        final List<String> serviceList = new ArrayList<String>();
        serviceList.add("MyService2");
        final Set<CredentialManagerEntity> serviceSet = new HashSet<CredentialManagerEntity>();

        final CredentialManagerEntity entity = new CredentialManagerEntity();
        entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
        entity.setEntityType(CredentialManagerEntityType.ENTITY);
        entity.setName("MyService");
        serviceSet.add(entity);
        when(credmServiceWeb.getServices()).thenReturn(serviceSet);
        final Response response = certificate.getReissueCertificate(serviceList);
        Assert.assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    @Test
    public void testReissueRestNotReady() {
        when(credMPkiConfBean.isEnabled()).thenReturn(false);

        final Response response = certificate.getReissueCertificate(null);
        Assert.assertEquals(Status.SERVICE_UNAVAILABLE.getStatusCode(), response.getStatus());
    }

}
