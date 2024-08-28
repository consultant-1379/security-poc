/*
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 */
package com.ericsson.oss.itpf.security.pki.common.util.constants;

/**
 * This class contains constants which will be used for common utility files.
 * 
 * @author xjagcho
 * 
 */
public final class Constants {
    public static final String X509 = "X.509";
    public static final String BASE64_REG_EXP = "([A-Za-z0-9+/]{4})*" + "([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)";
    public static final String NEW_LINE = System.lineSeparator();
    public static final String PKIX_BUILDER = "PKIX";

    public static final String JKS_FORMAT = "JKS";
    public static final String P12_FORMAT = "P12";
    public static final String PEM_FORMAT = "PEM";
    public static final String DER_FORMAT = "DER";
    public static final String JKS_EXTENSION = ".jks";
    public static final String P12_EXTENSION = ".p12";
    public static final String CRL_EXTENSION = ".crl";
    public static final String PEM_EXTENSION = ".pem";
    public static final String DER_EXTENSION = ".der";
    public static final int CRL_VERSION = 2;

    public final static String FILE_SEPARATOR = System.getProperty("file.separator");
    public final static String TMP_DIR = System.getProperty("java.io.tmpdir");
    public static final String NEXT_LINE = System.getProperty("line.separator");
    public static final String DSA_ALGORITHM = "DSA";
    public static final String RSA_ALGORITHM = "RSA";
    public static final String ECDSA_ALGORITHM = "ECDSA";
    public static final String DSA_ALGORITHM_URI = "http://www.w3.org/2009/xmldsig11#dsa-sha256";
    public static final String RSA_ALGORITHM_URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String ECDSA_ALGORITHM_URI = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    public static final String SIGNATURE = "Signature";
    public static final String MECHANISM_TYPE = "DOM";

    public static final String CN_ATTRIBUTE = "CN";
    public static final String COUNTRY_CODE_ATTRIBUTE = "C";
    public final static int CERTIFICATE_VERSION_V3 = 3;
    public final static int CERTIFICATE_VERSION_V2 = 2;
    public final static String SIMPLE_DATE_FORMAT = "yyyy-MMM-dd HH:mm:ss";
}
