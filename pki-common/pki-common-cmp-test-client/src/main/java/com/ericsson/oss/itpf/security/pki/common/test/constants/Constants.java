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
package com.ericsson.oss.itpf.security.pki.common.test.constants;

public class Constants {
    public static final String RESOURCES_PATH = "/src/test/resources/CertificatesTest";
    public static final String CA_NAME_IN_REQUEST = "MyRoot";
    public static final String RECIPIENT_SUBJECT_DN = "CN=example100";
    public static final String NODE_NAME_IN_REQUEST = "CN=Entity";
    public static final String KEY_ALGORITHM_IN_REQUEST = "RSA";
    public static final String SIGNATURE_ALGORITHM_IN_REQUEST = "SHA512WithRSA";
    public static final String KEY_SIZE_IN_REQUEST = "1024";
    public static final String KEY_LENGTH_IN_REQUEST = "1024";
    public static final String CMP_URL = "http://127.0.0.1:26772/cmp";
    public static final String NO_OF_PARALLEL_REQUESTS = "1";
    public static final String KEYSTORE_ALIAS = "racsa_omsas";
    public static final String JKS_KEYSTORE_TYPE = "jks";
    public static final String CERTIFICATE_FACTORY = "X.509";

    public static final String KEY_STORE_PATH = "/CertificatesTest/racsa_omsas.jks";

    public static final int CERT_REQUEST_ID = 1;
    public static final int IAK_REQUEST_ID = 100;
    public static final int IP_WITH_WAIT = 200;

    public static final String BC_SECURITY_PROVIDER = "BC";
    public static final String SIGNING_ALGORITHM = "SHA1withRSA";
    public static final String COMMON_NAME = "CN";

}
