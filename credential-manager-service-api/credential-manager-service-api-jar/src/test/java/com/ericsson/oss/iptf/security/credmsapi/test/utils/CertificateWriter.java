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
package com.ericsson.oss.iptf.security.credmsapi.test.utils;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.CertificateManager;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CertHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PrepareCertificate;

public class CertificateWriter {

    public static enum CertMode {
        valid, expired, notYetValid
    };

    public static List<KeystoreInfo> writeKeyAndCertificateJKS(final CertificateManager certificateManager, final CertMode mode) {

        return writeKeyAndCertificate(certificateManager, CertificateFormat.JKS, "/tmp/keyAndCertTest.jks", mode);
    }

    public static List<KeystoreInfo> writeKeyAndCertificatePKCS12(final CertificateManager certificateManager, final CertMode mode) {

        return writeKeyAndCertificate(certificateManager, CertificateFormat.PKCS12, "/tmp/keyAndCertTest.p12", mode);
    }

    public static List<KeystoreInfo> writeKeyAndCertificateBASE64(final CertificateManager certificateManager, final CertMode mode) {

        return writeKeyAndCertificate(certificateManager, CertificateFormat.BASE_64, "/tmp/keyAndCertTest.pem", mode);
    }

    public static List<KeystoreInfo> writeKeyAndCertificate(final CertificateManager certificateManager, final CertificateFormat certFormat, final String filename, final CertMode mode) {

        /*
         * Remove existing file (if any)
         */
        final File file = new File(filename);
        if (file.exists()) {
            file.delete();
        }

        /*
         * Create KeyPair parameter
         */
        final KeyPair keyPair = PrepareCertificate.createKeyPair();

        X509Certificate cert = null;
        switch (mode) {
        case valid:
            cert = PrepareCertificate.prepareCertificate(keyPair);
            break;
        case expired:
            cert = PrepareCertificate.prepareExpiredCertificate(keyPair);
            break;
        case notYetValid:
            cert = PrepareCertificate.prepareNotYetValidCertificate(keyPair);
            break;
        default:
            cert = PrepareCertificate.prepareCertificate(keyPair);
        }

        final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
        final KeystoreInfo ksInfo = new KeystoreInfo(filename, "", "", null, certFormat, "keyStorePwd", "Test");
        ksInfoList.add(ksInfo);

        certificateManager.setKeyPair(keyPair);
        certificateManager.setCertChain(new Certificate[] { cert });
        certificateManager.setCertHandler(new CertHandler());

        try {
            certificateManager.writeKeyAndCertificate(ksInfoList);
        } catch (final IssueCertificateException e) {
            e.printStackTrace();
            assertTrue("writeKeyAndCertificate: failed", false);
        }
        assertTrue("writeKeyAndCertificate: ok", true);
        return ksInfoList;

    }
}
