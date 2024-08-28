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
package com.ericsson.oss.itpf.security.pki.common.test.request.main;

import java.security.Security;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.test.request.WorkingMode;

public abstract class AbstractMain {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static Parameters configureParameters(final String[] args1) {
        final Parameters params = new Parameters();
        if (args1 == null) {
            params.setKeyAlgorithm(Constants.KEY_ALGORITHM_IN_REQUEST);
            params.setKeySize(Integer.valueOf(Constants.KEY_SIZE_IN_REQUEST));
            params.setKeyLengthInRequest(Integer.valueOf(Constants.KEY_LENGTH_IN_REQUEST));
            params.setSignatureAlgorithm(Constants.SIGNATURE_ALGORITHM_IN_REQUEST);
            params.setThreadId(1);
            params.setWorkingDirectory(Constants.RESOURCES_PATH);
            params.setNodeName(Constants.NODE_NAME_IN_REQUEST);
            params.setSendTransactionID(true);
            params.setMode(WorkingMode.POSITIVE_IR);
            params.setRecipientSubjectDN(Constants.RECIPIENT_SUBJECT_DN);
            params.setVendorTrustedCA(Constants.CA_NAME_IN_REQUEST);
            params.setUrl(Constants.CMP_URL);
        }
        return params;
    }

}
