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
package com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.JUnitConstants;

@RunWith(MockitoJUnitRunner.class)
public class ConfigurationListenerTest {
    @InjectMocks
    private ConfigurationListener configurationListener;

    @Mock
    private Logger logger;

    /**
     * Test case to test the listenForAnykeyStoreFilePathChange method
     */
    @Test
    public void testListenForAnykeyStoreFilePathChange() {
        configurationListener.listenForAnykeyStoreFilePathChange(JUnitConstants.filePath);
        Mockito.verify(logger).debug("Configuration change listener invoked since the keyStoreFilePath value has got changed in the model. The new keyStoreFilePath is {}", JUnitConstants.filePath);
    }

    /**
     * Test case to test the listenForAnykeyStoreFileTypeChange method
     */
    @Test
    public void testListenForAnykeyStoreFileTypeChange() {
        configurationListener.listenForAnykeyStoreFileTypeChange(JUnitConstants.keyStoreType);
        Mockito.verify(logger)
                .debug("Configuration change listener invoked since the keyStoreFileType value has got changed in the model. The new keyStoreFileType is {}", JUnitConstants.keyStoreType);
    }

    /**
     * Test case to test the listenForAnyScepRequestRecordPurgePeriodChange method
     */
    @Test
    public void testListenForAnyScepRequestRecordPurgePeriodChange() {
        configurationListener.listenForAnyScepRequestRecordPurgePeriodChange(JUnitConstants.scepRequestRecordPurgePeriod);
        Mockito.verify(logger).debug("Configuration change listener invoked since the scepRequestRecordPurgePeriod value has got changed in the model. The new scepRequestRecordPurgePeriod is {}",
                JUnitConstants.scepRequestRecordPurgePeriod);
    }

    /**
     * Test case to test the listenForAnySchedulerTimeChange method
     */
    @Test
    public void testListenForAnySchedulerTimeChange() {
        configurationListener.listenForAnyScepDBCleanupSchedulerTimeChange(JUnitConstants.scepDBCleanupSchedulerTime);
        Mockito.verify(logger).debug("Configuration change listener invoked since the scepDBCleanupSchedulerTime value has got changed in the model. The new scepDBCleanupSchedulerTime is {}",
                JUnitConstants.scepDBCleanupSchedulerTime);
    }

    /**
     * Test case to test the listenForAnykeyStoreFileTypeChange method
     */
    @Test
    public void testListenForAnyScepRAInfraCertAliasNameChange() {
        configurationListener.listenForAnyScepRAInfraCertAliasNameChange(JUnitConstants.caName);
        Mockito.verify(logger).debug("Configuration change listener invoked since the scepRAInfraCertAliasName value has got changed in the model. The new scepRAInfraCertAliasName is {}",
                JUnitConstants.caName);
    }

    /**
     * Test case to test the listenForAnykeyStoreFileTypeChange method
     */
    @Test
    public void testListenForAnyScepRATrustStoreFilePathChange() {
        configurationListener.listenForAnyScepRATrustStoreFilePathChange(JUnitConstants.filePath);
        Mockito.verify(logger).debug("Configuration change listener invoked since the scepRATrustStoreFilePath value has got changed in the model. The new scepRATrustStoreFilePath is {}",
                JUnitConstants.filePath);
    }

    /**
     * Test case to test the listenForAnykeyStoreFileTypeChange method
     */
    @Test
    public void testLlistenForAnyTrustStoreFileTypeChange() {
        configurationListener.listenForAnyTrustStoreFileTypeChange(JUnitConstants.keyStoreType);
        Mockito.verify(logger).debug("Configuration change listener invoked since the trustStoreFileType value has got changed in the model. The new trustStoreFileType is {}",
                JUnitConstants.keyStoreType);
    }

    /**
     * Test case to test the listenForcRLPathChanges method
     */
    @Test
    public void testListenForcRLPathChanges() {
        configurationListener.listenForScepCRLPathChanges(JUnitConstants.CrlPath);
        Mockito.verify(logger).debug("Configuration change listener invoked since the scepCRLPath value has got changed in the model. The new scepCRLPath is {}", JUnitConstants.CrlPath);
    }

    /**
     * Test case to test the getKeyStoreFilePath method
     */
    @Test
    public void testgetKeyStoreFilePath() {
        configurationListener.getKeyStoreFilePath();
    }

    /**
     * Test case to test the getKeyStoreFileType method
     */
    @Test
    public void testgetKeyStoreFileType() {
        configurationListener.getKeyStoreFileType();
    }

    /**
     * Test case to test the getScepRequestRecordPurgePeriod method
     */
    @Test
    public void testgetScepRequestRecordPurgePeriod() {
        configurationListener.getScepRequestRecordPurgePeriod();
    }

    /**
     * Test case to test the getSchedulerTime method
     */
    @Test
    public void testgetSchedulerTime() {
        configurationListener.getScepDBCleanupSchedulerTime();
    }

    /**
     * Test case to test the getScepRAInfraCertAliasName method
     */
    @Test
    public void testgetScepRAInfraCertAliasName() {
        configurationListener.getScepRAInfraCertAliasName();
    }

    /**
     * Test case to test the getScepRATrustStoreFilePath method
     */
    @Test
    public void testgetScepRATrustStoreFilePath() {
        configurationListener.getScepRATrustStoreFilePath();
    }

    /**
     * Test case to test the getTrustStoreFileType method
     */
    @Test
    public void testgetTrustStoreFileType() {
        configurationListener.getTrustStoreFileType();
    }

    /**
     * Test case to test the getcRLPath method
     */
    @Test
    public void testGetScepCRLPath() {
        configurationListener.getScepCRLPath();
    }
}