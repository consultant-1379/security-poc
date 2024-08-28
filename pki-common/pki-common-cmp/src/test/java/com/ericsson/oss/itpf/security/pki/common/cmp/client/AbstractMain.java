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
package com.ericsson.oss.itpf.security.pki.common.cmp.client;

import java.security.Security;

import com.ericsson.oss.itpf.security.pki.common.cmp.client.AbstractRequestResponse.WorkingMode;

public abstract class AbstractMain {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static Parameters getParams(String[] args1) throws Exception {
        String[] args = new String[10];

        if (args1 == null) {
            args = new String[10];
            args[0] = "/src/test/resources/CertificatesTest";
            args[1] = "MyRoot";
            args[2] = "CN=example100";
            args[3] = "CN=Entity";
            args[4] = "RSA";
            args[5] = "SHA512WithRSA";
            args[6] = "1024";
            args[7] = "1";
            args[8] = "1024";
            args[9] = "http://127.0.0.1:26772/cmp";
        }

        else if (args.length != 10) {
            throw new Exception();
        }

        Parameters params = new Parameters();

        String workingDirectory = args[0];
        String vendorTrustedCA = args[1];
        String recipientSubjectDN = args[2];
        String nodeName = args[3];
        String keyAlgorithm = args[4];
        String signatureAlgorithm = args[5];
        int keySize = Integer.valueOf(args[6]);
        int keyLengthInRequest = Integer.valueOf(args[8]);
        String url = args[9];

        params.setKeyAlgorithm(keyAlgorithm);
        params.setKeySize(keySize);
        params.setKeyLengthInRequest(keyLengthInRequest);
        params.setSignatureAlgorithm(signatureAlgorithm);
        params.setThreadId(1);
        params.setWorkingDirectory(workingDirectory);
        params.setNodeName(nodeName);
        params.setSendTransactionID(true);
        params.setMode(WorkingMode.POSITIVE_IR);
        params.setRecipientSubjectDN(recipientSubjectDN);
        params.setVendorTrustedCA(vendorTrustedCA);
        params.setUrl(url);

        return params;
    }

}
