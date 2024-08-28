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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x500.X500Name;

public class CertificateResponseMessageBuilderUtility {

    private static final String X_509 = "x.509";

    public static List<X509Certificate> getVendorCertsList(String isssueName) throws Exception {

        final List<X509Certificate> vendorCertSet = new ArrayList<X509Certificate>();
        // final String vendorCertPath = CertificateResponseMessageBuilder.class.getResource("/Certificates/" + isssueName + ".crt").getPath();
        final String vendorCertPath = "src/test/resources/CertificatesTest/MyRoot.crt";
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(X_509);
        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(vendorCertPath);
            final X509Certificate vendorCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            vendorCertSet.add(vendorCert);
        } finally {
            if (fileInputStream != null) {
                fileInputStream.close();
            }
        }
        return vendorCertSet;
    }

    public static X509Certificate identifyUserCertAndCertChains(CMPCertificate[] extraCerts, String senderName) throws Exception {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(X_509);
        boolean isUserCert = true;
        X509Certificate userCertificate = null;
        for (CMPCertificate eachCert : extraCerts) {
            if (eachCert.isX509v3PKCert()) {
                X500Name certSubjectName = eachCert.getX509v3PKCert().getSubject();
                if (StringUtility.isEquals(certSubjectName, senderName) && isUserCert) {
                    isUserCert = false;
                    ASN1InputStream inputStream = new ASN1InputStream(eachCert.getEncoded());
                    userCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
                }
            }
        }
        return userCertificate;

    }

}
