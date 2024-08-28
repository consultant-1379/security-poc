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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

@RunWith(MockitoJUnitRunner.class)
public class ConfigurationParamsListenerTest {

    @InjectMocks
    ConfigurationParamsListener configurationParamsListener;

    @Mock
    Logger logger;

    private static final int NODE_WAIT_TIME_BEFORE_POLLING = 10;
    private static final int REQUEST_TIMEOUT = 60;
    private static final String ALGORITHM_FOR_IAK_SIGNING = "iak";
    private static final String KEYSTORE_ALIAS = "keyStore";
    private static final String KEYSTORE_FILE_TYPE = "keyStore";
    private static final String KEYSTORE = "keyStore";
    private static final String VENDOR_TRUST_STORE_FILE_TYPE = "vendorTrust";
    private static final String VENDORE_CERTIFICATE_PATH = "vendorCertificate";
    private static final String CA_TRUST_STORE_FILE_TYPE = "caTrustStore";
    private static final String CA_CERTIFICATE_PATH = "caCertPath";
    private static final String CRL_PATH = "cRLPath";
    private static final String timeToSet = "1,2,30";

    @Test
    public void testListenForcRLPathChanges() {
        configurationParamsListener.listenForcRLPathChanges(CRL_PATH);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", CRL_PATH);
    }

    @Test
    public void testListenForNodeWaitTimeBeforePollRequest() {
        configurationParamsListener.listenForNodeWaitTimeBeforePollRequest(NODE_WAIT_TIME_BEFORE_POLLING);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}" , NODE_WAIT_TIME_BEFORE_POLLING);
    }

    @Test
    public void testListenForRequestTimeout() {
        configurationParamsListener.listenForRequestTimeout(REQUEST_TIMEOUT);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}" , REQUEST_TIMEOUT);
    }

    @Test
    public void testListenForAlgorithmForIAKSigning() {
        configurationParamsListener.listenForAlgorithmForIAKSigning(ALGORITHM_FOR_IAK_SIGNING);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}" , ALGORITHM_FOR_IAK_SIGNING);

    }

    @Test
    public void testListenForKeyStorealiasChanges() {
        configurationParamsListener.listenForKeyStorealiasChanges(KEYSTORE_ALIAS);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", KEYSTORE_ALIAS);

    }

    @Test
    public void testListenForKeyStoreFileTypeChanges() {
        configurationParamsListener.listenForKeyStoreFileTypeChanges(KEYSTORE_FILE_TYPE);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", KEYSTORE_FILE_TYPE);

    }

    @Test
    public void testListenForKeyStorePathChanges() {
        configurationParamsListener.listenForKeyStorePathChanges(KEYSTORE);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", KEYSTORE);

    }

    @Test
    public void testListenForVendorTrustStoreFileTypeChanges() {
        configurationParamsListener.listenForVendorTrustStoreFileTypeChanges(VENDOR_TRUST_STORE_FILE_TYPE);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", VENDOR_TRUST_STORE_FILE_TYPE);

    }

    @Test
    public void testListenForVendorCertificatesPathChanges() {
        configurationParamsListener.listenForVendorCertificatesPathChanges(VENDORE_CERTIFICATE_PATH);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", VENDORE_CERTIFICATE_PATH);

    }

    @Test
    public void testListenForCATrustStoreFileTypeChanges() {
        configurationParamsListener.listenForCATrustStoreFileTypeChanges(CA_TRUST_STORE_FILE_TYPE);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", CA_TRUST_STORE_FILE_TYPE);

    }

    @Test
    public void testListenForCACertificatesPathChanges() {
        configurationParamsListener.listenForCACertificatesPathChanges(CA_CERTIFICATE_PATH);
        Mockito.verify(logger).info("Default  value have been replaced with new changed value for the configuration parameter {}", CA_CERTIFICATE_PATH);
    }

    @Test
    public void testSetCRLPath() {
        configurationParamsListener.setCRLPath(CRL_PATH);
        Assert.assertTrue(configurationParamsListener.getCRLPath() == "cRLPath");

    }

    @Test
    public void testSetKeyStorePath() {
        configurationParamsListener.setKeyStorePath("path");
        Assert.assertTrue(configurationParamsListener.getKeyStorePath() == "path");
    }

    @Test
    public void testSetKeyStoreAlias() {
        configurationParamsListener.setKeyStoreAlias("alias");

        Assert.assertEquals(configurationParamsListener.getKeyStoreAlias(), "alias");

    }

    @Test
    public void testSetKeyStoreFileType() {
        configurationParamsListener.setKeyStoreFileType(KEYSTORE_FILE_TYPE);
        Assert.assertTrue(configurationParamsListener.getKeyStoreFileType() == "keyStore");
    }

    @Test
    public void testSetNodeWaitTimeBeforePollRequest() {
        configurationParamsListener.setNodeWaitTimeBeforePollRequest(10);

        Assert.assertEquals(configurationParamsListener.getNodeWaitTimeBeforePollRequest(), 10);

    }

    @Test
    public void testSetRequestTimeOut() {
        configurationParamsListener.setRequestTimeOut(130);
        Assert.assertEquals(configurationParamsListener.getRequestTimeOut(), 130);
    }

    @Test
    public void testSetAlgorithmForIAKSigning() {
        configurationParamsListener.setAlgorithmForIAKSigning("IAK");
        Assert.assertEquals(configurationParamsListener.getAlgorithmForIAKSigning(), "IAK");
    }

    @Test
    public void testSetVendorCertPath() {
        configurationParamsListener.setVendorCertPath("path");
        Assert.assertEquals(configurationParamsListener.getVendorCertPath(), "path");
    }

    @Test
    public void testSetVendorTrustStoreFileType() {
        configurationParamsListener.setVendorTrustStoreFileType("filetype");
        Assert.assertEquals(configurationParamsListener.getVendorTrustStoreFileType(), "filetype");
    }

    @Test
    public void testSetCACertPath() {
        configurationParamsListener.setCACertPath("CACertpath");
        Assert.assertEquals(configurationParamsListener.getCACertPath(), "CACertpath");
    }

    @Test
    public void testSetCATrustStoreFileType() {
        configurationParamsListener.setCATrustStoreFileType("caTrustStoreFileType");
        Assert.assertEquals(configurationParamsListener.getCATrustStoreFileType(), "caTrustStoreFileType");
    }

    @Test
    public void testSetDbMaintenanceSchedulerInterval() {
        configurationParamsListener.setDbMaintenanceSchedulerInterval("dbMaintenanceSchedulerInterval");
        Assert.assertEquals(configurationParamsListener.getDbMaintenanceSchedulerInterval(), "dbMaintenanceSchedulerInterval");
    }

    @Test
    public void testSetcMPRAInfraCertAliasName() {
        String cMPRAInfraCertAliasName = "cMPRAInfraCertAliasName";
        configurationParamsListener.setCMPRAInfraCertAliasName(cMPRAInfraCertAliasName);
        Assert.assertEquals(configurationParamsListener.getCMPRAInfraCertAliasName(), "cMPRAInfraCertAliasName");
    }

}
