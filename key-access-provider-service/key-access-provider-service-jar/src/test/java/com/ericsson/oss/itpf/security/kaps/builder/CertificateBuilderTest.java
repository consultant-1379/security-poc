/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.builder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.kaps.common.BaseTest;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509v3CertificateBuilderHolder;

@RunWith(MockitoJUnitRunner.class)
public class CertificateBuilderTest extends BaseTest {

    @InjectMocks
    CertificateBuilder certificateBuilder;

    @Mock
    SubjectPublicKeyInfo subjectPublicKeyInfo;

    private KeyIdentifier keyIdentifier;
    private PublicKey publicKey;
    private KeyPair keyPair;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId("1");
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
    }

    @Test
    public void testBuildX509v3CertificateBuilder() throws IOException, InvalidCertificateExtensionsException {
        final X509v3CertificateBuilderHolder x509v3CertBuilderHolder = new X509v3CertificateBuilderHolder();
        x509v3CertBuilderHolder.setIssuerDN("CN=CN_PKI");
        x509v3CertBuilderHolder.setSerialNumber(new BigInteger("123456789"));
        x509v3CertBuilderHolder.setSubjectDN("CN=CN_PKI");
        x509v3CertBuilderHolder.setNotAfter(new Date());
        x509v3CertBuilderHolder.setNotBefore(new Date());
        x509v3CertBuilderHolder.setIssuerUniqueIdentifier(true);
        x509v3CertBuilderHolder.setSubjectUniqueIdentifier(true);
        x509v3CertBuilderHolder.setSubjectUniqueIdentifierValue("nmsadm");
        x509v3CertBuilderHolder.setSubjectPublicKey(publicKey);

        List<Extension> extensions = new ArrayList<Extension>();
        final Extension extension = new Extension(Extension.basicConstraints, false, new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(1)));
        extensions.add(extension);
        List<CertificateExtensionHolder> certificateExtensionHolders = new ArrayList<CertificateExtensionHolder>();
        for (final Extension ext : extensions) {
            if (extension != null) {
                final CertificateExtensionHolder certificateExtensionHolder = new CertificateExtensionHolder(extension.getExtnId().getId(), extension.isCritical(), extension.getExtnValue()
                        .getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
                logger.debug("Added extension for building X509Certificate {} ", extension.getExtnId());
            }

        }
        x509v3CertBuilderHolder.setCertificateExtensionHolders(certificateExtensionHolders);

        certificateBuilder.buildX509v3CertificateBuilder(x509v3CertBuilderHolder, new X500Principal("CN=" + "CN_PKI"));
    }

}
