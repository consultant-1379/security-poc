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
import java.security.*;
import java.util.*;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.kaps.common.BaseTest;
import com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.*;

@RunWith(MockitoJUnitRunner.class)
public class CRLBuilderTest extends BaseTest {

    @InjectMocks
    CRLBuilder crlBuilder;

    @Mock
    Logger logger;

    private KeyIdentifier keyIdentifier;
    private KeyPair keyPair;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId("1");
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    @Test
    public void testBuildX509v2CRLBuilder() throws IOException, InvalidCRLExtensionsException {
        final X509v2CRLBuilderHolder x509v2CRLBuilderHolder = new X509v2CRLBuilderHolder();
        x509v2CRLBuilderHolder.setSubjectDN("CN=CN_PKI");
        x509v2CRLBuilderHolder.setThisUpdate(new Date());
        x509v2CRLBuilderHolder.setNextUpdate(new Date());

        List<Extension> extensions = new ArrayList<Extension>();
        final Extension extension =
                new Extension(Extension.basicConstraints, false, new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(1)));
        extensions.add(extension);
        List<CertificateExtensionHolder> certificateExtensionHolders = new ArrayList<CertificateExtensionHolder>();
        for (final Extension ext : extensions) {
            if (extension != null) {
                final CertificateExtensionHolder certificateExtensionHolder =
                        new CertificateExtensionHolder(extension.getExtnId().getId(), extension.isCritical(), extension.getExtnValue()
                                .getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
                logger.debug("Added extension for building X509Certificate {} ", extension.getExtnId());
            }

        }
        RevokedCertificateInfoHolder revokedCertificateInfoHolder = new RevokedCertificateInfoHolder("1234567890", new Date(), 1, new Date());
        x509v2CRLBuilderHolder.setExtensionHolders(certificateExtensionHolders);
        final List<RevokedCertificateInfoHolder> revokedCertificatesInfoHolders = new ArrayList<RevokedCertificateInfoHolder>();
        revokedCertificatesInfoHolders.add(revokedCertificateInfoHolder);
        x509v2CRLBuilderHolder.setRevokedCertificateInfoHolders(revokedCertificatesInfoHolders);
        crlBuilder.buildX509v2CRLBuilder(x509v2CRLBuilderHolder, new X500Principal("CN=" + "CN_PKI"));
    }

    @Test
    public void testBuildX509v2CRLBuilder2() throws IOException, InvalidCRLExtensionsException {
        final X509v2CRLBuilderHolder x509v2CRLBuilderHolder = new X509v2CRLBuilderHolder();
        x509v2CRLBuilderHolder.setSubjectDN("CN=CN_PKI");
        x509v2CRLBuilderHolder.setThisUpdate(new Date());
        x509v2CRLBuilderHolder.setNextUpdate(new Date());

        List<Extension> extensions = new ArrayList<Extension>();
        final Extension extension =
                new Extension(Extension.basicConstraints, false, new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(1)));
        extensions.add(extension);
        List<CertificateExtensionHolder> certificateExtensionHolders = new ArrayList<CertificateExtensionHolder>();
        for (final Extension ext : extensions) {
            if (extension != null) {
                final CertificateExtensionHolder certificateExtensionHolder =
                        new CertificateExtensionHolder(extension.getExtnId().getId(), extension.isCritical(), extension.getExtnValue()
                                .getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
                logger.debug("Added extension for building X509Certificate {} ", extension.getExtnId());
            }

        }
        RevokedCertificateInfoHolder revokedCertificateInfoHolder = new RevokedCertificateInfoHolder("1234567890", new Date(), 1, null);
        x509v2CRLBuilderHolder.setExtensionHolders(certificateExtensionHolders);
        final List<RevokedCertificateInfoHolder> revokedCertificatesInfoHolders = new ArrayList<RevokedCertificateInfoHolder>();
        revokedCertificatesInfoHolders.add(revokedCertificateInfoHolder);
        x509v2CRLBuilderHolder.setRevokedCertificateInfoHolders(revokedCertificatesInfoHolders);
        crlBuilder.buildX509v2CRLBuilder(x509v2CRLBuilderHolder, new X500Principal("CN=" + "CN_PKI"));
    }

}
