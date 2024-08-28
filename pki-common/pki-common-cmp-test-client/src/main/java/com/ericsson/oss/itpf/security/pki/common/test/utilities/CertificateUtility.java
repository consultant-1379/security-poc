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
package com.ericsson.oss.itpf.security.pki.common.test.utilities;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.*;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;

public class CertificateUtility {

    public static X509Certificate readCertificateFromPath(final String certificateFilePath) throws IOException, CertificateException {
        FileInputStream fileInputStream = null;
        X509Certificate x509Certificate = null;
        try {
            fileInputStream = new FileInputStream(certificateFilePath);
            final CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.CERTIFICATE_FACTORY);
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        } finally {
            if (fileInputStream != null) {
                fileInputStream.close();
            }
        }
        return x509Certificate;
    }

}
