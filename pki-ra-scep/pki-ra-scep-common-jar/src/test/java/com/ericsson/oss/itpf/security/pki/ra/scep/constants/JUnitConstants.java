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
package com.ericsson.oss.itpf.security.pki.ra.scep.constants;

/**
 * This class contains the constants which are used as part of the test cases
 */
public class JUnitConstants {

    public static final String keyStoreType = "PKCS12";
    public static final String filePath = "/LTEIPSecNEcus_Sceprakeystore_1.p12";
    public static final String password = "C4bCzXyT";
    public static final String scepDBCleanupSchedulerTime = "*,*,*,*,0,1,0";
    public static final int scepRequestRecordPurgePeriod = 7;
    public static final String caName = "lteipsecnecus";
    public static final String rootCaName = "LTEIPSecNEcusRootCA";
    public static final String transactionId = "1.2.3.4";
    public static final int messageType = 19;
    public static final String jks_keyStoreType = "JKS";
    public static final String trustStoreFilePath = "/SCEPRAServerTrustStore.jks";
    public static final String CrlPath = "/Crls/SCEPCRL_ENM_Management_CA.crl";
    public static final String TRUST_STORE = "TrustStore";
    public static final String TRUST_STORE_CERT_CA_NAME = "ENM_OAM_CA";
    public static final String TRUST_STORE_CERT_ALIAS_NAME = "oam_enm_oam_ca";
}
