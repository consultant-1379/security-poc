/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.util;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;

public class CertificateUtils {

    private CertificateUtils() {
    } //Only static methods

    public static PKCS10CertificationRequest generatePKCS10Request(final String signatureAlgorithm, final X500Name x500Name, final KeyPair keyPair, final ASN1Set attributes, final String provider)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        String securityProvider = provider;
        if (securityProvider == null || securityProvider.equals("")) {
            securityProvider = BouncyCastleProvider.PROVIDER_NAME;
        }

        final JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(x500Name, keyPair.getPublic());
        final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);

        PKCS10CertificationRequest csr = null;
        try {
            final ContentSigner signer = signerBuilder.build(keyPair.getPrivate());
            csr = csrBuilder.build(signer);
        } catch (final OperatorCreationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();

        }

        return csr;

    }

    public static PKCS10CertificationRequest generatePKCS10Request(final String signatureAlgorithm, final CredentialManagerEntity entity, final KeyPair keyPair, final ASN1Set attributes,
                                                                   final String provider) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {

        final X500Name name = new X500Name(entity.getSubject().retrieveSubjectDN());
        return generatePKCS10Request(signatureAlgorithm, name, keyPair, attributes, provider);

    }
    
    /**
     * @param dnWithCn
     * @return
     */

    public static String getCN(final String dnWithCn) {

        if (dnWithCn.contains(",")) {

            final String str[] = dnWithCn.split(",");

            for (int i = 0; i < str.length; i++) {
                if (str[i].contains("=")) {
                    final String[] istr = str[i].split("=");
                    if (istr[0].contains("CN") || istr[0].contains("cn")) {
                        return istr[1];
                    }
                }
            }
        } else if (dnWithCn.contains("=")) {
            final String[] istr = dnWithCn.split("=");
            if (istr[0].contains("CN") || istr[0].contains("cn")) {
                return istr[1];
            }
        }
        return dnWithCn;
    }
}
