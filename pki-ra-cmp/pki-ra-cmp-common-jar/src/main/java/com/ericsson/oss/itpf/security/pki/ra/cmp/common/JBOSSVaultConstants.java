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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

/**
 * These constants are the Jboss vault properties defined for sensitive data
 * like passwords.
 * <p>
 * Properties are:<br>
 * 1.CA_TRUST_PASSWORD_PROPERTY which is password property within Jboss vault
 * for Internal trusts JKS file.<br>
 * 2.VENDOR_TRUST_PASSWORD_PROPERTY which is password property within Jboss
 * vault for External trusts JKS file.<br>
 * 3.RA_KEYSTORE_PASSWORD_PROPERTY which is password property with Jboss vault
 * for RA and its chain JKS file
 * <p>
 * Note: it need not be only JKS file but can be any keyStore for eg: pem/pkcs12
 * etc.
 *
 * @author tcsdemi
 *
 */
public class JBOSSVaultConstants {

    private JBOSSVaultConstants() {
    }

    public static final String CA_TRUST_AUTHENTICATION_CODE = "CMP_CA_TRUST_PASSWORD_PROPERTY";
    public static final String VENDOR_TRUST_AUTHENTICATION_CODE = "CMP_VENDOR_TRUST_PASSWORD_PROPERTY";
    public static final String RA_KEYSTORE_AUTHENTICATION_CODE = "CMP_RA_KEYSTORE_PASSWORD_PROPERTY";

}
