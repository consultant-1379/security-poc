package com.ericsson.oss.itpf.security.pki.ra.cmp.test.utils;

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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.vc.DigitalSignatureValidatorTest;

public class BaseDigitalSignatureValidatorTestUtil {

    private BaseDigitalSignatureValidatorTestUtil() {

    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(BaseDigitalSignatureValidatorTestUtil.class);

    public static Map<String, Set<X509Certificate>> getCertAndCertChain(final RequestMessage pKIRequestMessage) {
        HashMap<String, Set<X509Certificate>> certAndCertChainMap = null;
        X509Certificate userCertificate = null;
        Set<X509Certificate> userCertSet = null;

        userCertSet = new HashSet<X509Certificate>();
        userCertificate = pKIRequestMessage.getUserCertificate();
        userCertSet.add(userCertificate);
        certAndCertChainMap = new HashMap<String, Set<X509Certificate>>();

        return certAndCertChainMap;

    }

    public static Set<X509Certificate> getVendorCerts() {
        Set<X509Certificate> vendorCertSet = null;
        CertificateFactory certificateFactory;
        X509Certificate vendorCert;
        FileInputStream fileInputStream;
        String vendorCertPath = null;

        vendorCertPath = DigitalSignatureValidatorTest.class.getResource("/Certificates/verifyDigiSignature_vendorCerts/MyRoot.crt").getPath();
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
            fileInputStream = new FileInputStream(vendorCertPath);
            vendorCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            vendorCertSet = new HashSet<X509Certificate>();
            vendorCertSet.add(vendorCert);
        } catch (CertificateException | FileNotFoundException e) {
            LOGGER.warn("src/test/resources do not contain Vendor certs.");
        }
        return vendorCertSet;
    }

}
