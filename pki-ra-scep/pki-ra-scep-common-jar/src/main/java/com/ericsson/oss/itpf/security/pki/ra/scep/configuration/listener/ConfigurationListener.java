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

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.modeling.annotation.constraints.NotNull;
import com.ericsson.oss.itpf.sdk.config.annotation.ConfigurationChangeNotification;
import com.ericsson.oss.itpf.sdk.config.annotation.Configured;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;

/**
 * ConfigurationListener class fetches the configuration parameters from the model using the property name. Configuration parameters for SCEP service includes the properties of key store file which
 * are key store file path and key store file type.
 * 
 * @author xnagsow
 */
@ApplicationScoped
@Profiled
public class ConfigurationListener {

    @Inject
    private Logger logger;

    @Inject
    @NotNull
    @Configured(propertyName = "keyStoreFilePath")
    private String keyStoreFilePath;

    @Inject
    @NotNull
    @Configured(propertyName = "keyStoreFileType")
    private String keyStoreFileType;

    @Inject
    @NotNull
    @Configured(propertyName = "scepRequestRecordPurgePeriod")
    private int scepRequestRecordPurgePeriod;

    @Inject
    @NotNull
    @Configured(propertyName = "scepDBCleanupSchedulerTime")
    private String scepDBCleanupSchedulerTime;

    @Inject
    @NotNull
    @Configured(propertyName = "scepRAInfraCertAliasName")
    private String scepRAInfraCertAliasName;

    @Inject
    @NotNull
    @Configured(propertyName = "scepRATrustStoreFilePath")
    private String scepRATrustStoreFilePath;

    @Inject
    @NotNull
    @Configured(propertyName = "trustStoreFileType")
    private String trustStoreFileType;

    @Inject
    @NotNull
    @Configured(propertyName = "scepCRLPath")
    private String scepCRLPath;

    /**
     * This method is used to listen any changes occurred in configuration environment for the property keyStoreFilePath and update the default value with the new value for the changed property.
     * 
     * @param keyStoreFilePath
     *            This parameter is used to listen the keyStoreFilePath from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.keyStoreFilePath is to be changed with the new value.
     */

    public void listenForAnykeyStoreFilePathChange(@Observes @ConfigurationChangeNotification(propertyName = "keyStoreFilePath") final String keyStoreFilePath) {
        logger.debug("listenForAnykeyStoreFilePathChange invoked");
        if (keyStoreFilePath != null) {
            logger.debug("Configuration change listener invoked since the keyStoreFilePath value has got changed in the model. The new keyStoreFilePath is {}", keyStoreFilePath);
            this.keyStoreFilePath = keyStoreFilePath;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property keyStoreFileType and update the default value with the new value for the changed property.
     * 
     * @param keyStoreFileType
     *            This parameter is used to listen the keyStoreFileType from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.keyStoreFileType is to be changed with the new value.
     */

    public void listenForAnykeyStoreFileTypeChange(@Observes @ConfigurationChangeNotification(propertyName = "keyStoreFileType") final String keyStoreFileType) {

        logger.debug("listenForAnykeyStoreFileTypeChange invoked");

        if (keyStoreFileType != null) {
            logger.debug("Configuration change listener invoked since the keyStoreFileType value has got changed in the model. The new keyStoreFileType is {}", keyStoreFileType);
            this.keyStoreFileType = keyStoreFileType;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property scepRequestRecordPurgePeriod and update the default value with the new value for the changed
     * property.
     * 
     * @param scepRequestRecordPurgePeriod
     *            This parameter is used to listen the scepRequestRecordPurgePeriod from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.scepRequestRecordPurgePeriod is to be changed with the new value.
     */

    public void listenForAnyScepRequestRecordPurgePeriodChange(@Observes @ConfigurationChangeNotification(propertyName = "scepRequestRecordPurgePeriod") final int scepRequestRecordPurgePeriod) {
        logger.debug("listenForAnyscepRequestRecordPurgePeriodChange invoked");
        if (scepRequestRecordPurgePeriod != 0) {
            logger.debug("Configuration change listener invoked since the scepRequestRecordPurgePeriod value has got changed in the model. The new scepRequestRecordPurgePeriod is {}",
                    scepRequestRecordPurgePeriod);
            this.scepRequestRecordPurgePeriod = scepRequestRecordPurgePeriod;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property scepDBCleanupSchedulerTime and update the default value with the new value for the changed
     * property.
     * 
     * @param scepDBCleanupSchedulerTime
     *            This parameter is used to listen the scepDBCleanupSchedulerTime from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.scepDBCleanupSchedulerTime is to be changed with the new value.
     */

    public void listenForAnyScepDBCleanupSchedulerTimeChange(@Observes @ConfigurationChangeNotification(propertyName = "scepDBCleanupSchedulerTime") final String scepDBCleanupSchedulerTime) {

        logger.debug("listenForAnySchedulertimeChange invoked");

        if (scepDBCleanupSchedulerTime != null) {
            logger.debug("Configuration change listener invoked since the scepDBCleanupSchedulerTime value has got changed in the model. The new scepDBCleanupSchedulerTime is {}",
                    scepDBCleanupSchedulerTime);
            this.scepDBCleanupSchedulerTime = scepDBCleanupSchedulerTime;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property scepRAInfraCertAliasName and update the default value with the new value for the changed
     * property.
     * 
     * @param scepRAInfraCertAliasName
     *            This parameter is used to listen the scepRAInfraCertAliasName from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.scepRAInfraCertAliasName is to be changed with the new value.
     */

    public void listenForAnyScepRAInfraCertAliasNameChange(@Observes @ConfigurationChangeNotification(propertyName = "scepRAInfraCertAliasName") final String scepRAInfraCertAliasName) {

        logger.info("listenForAnyScepRAInfraCertAliasNameChange invoked");

        if (scepRAInfraCertAliasName != null) {
            logger.debug("Configuration change listener invoked since the scepRAInfraCertAliasName value has got changed in the model. The new scepRAInfraCertAliasName is {}",
                    scepRAInfraCertAliasName);
            this.scepRAInfraCertAliasName = scepRAInfraCertAliasName;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property scepRATrustStoreFilePath and update the default value with the new value for the changed
     * property.
     * 
     * @param scepRATrustStoreFilePath
     *            This parameter is used to listen the scepRATrustStoreFilePath from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.scepRATrustStoreFilePath is to be changed with the new value.
     */

    public void listenForAnyScepRATrustStoreFilePathChange(@Observes @ConfigurationChangeNotification(propertyName = "scepRATrustStoreFilePath") final String scepRATrustStoreFilePath) {

        logger.info("listenForAnyScepRATrustStoreFilePathChange invoked");

        if (scepRATrustStoreFilePath != null) {
            logger.debug("Configuration change listener invoked since the scepRATrustStoreFilePath value has got changed in the model. The new scepRATrustStoreFilePath is {}",
                    scepRATrustStoreFilePath);
            this.scepRATrustStoreFilePath = scepRATrustStoreFilePath;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property trustStoreFileType and update the default value with the new value for the changed property.
     * 
     * @param trustStoreFileType
     *            This parameter is used to listen the trustStoreFileType from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.trustStoreFileType is to be changed with the new value.
     */

    public void listenForAnyTrustStoreFileTypeChange(@Observes @ConfigurationChangeNotification(propertyName = "trustStoreFileType") final String trustStoreFileType) {

        logger.info("listenForAnyTrustStoreFileTypeChange invoked");

        if (trustStoreFileType != null) {
            logger.debug("Configuration change listener invoked since the trustStoreFileType value has got changed in the model. The new trustStoreFileType is {}", trustStoreFileType);
            this.trustStoreFileType = trustStoreFileType;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property cRLPath and update the default value with the new value for the changed property.
     * 
     * @param cRLPath
     *            This parameter is used to listen the cRLPath from the pki-ra-scep-model. Whenever the value changes, it has to be listened by this parameter and the value of this.cRLPath is to be
     *            changed with the new value.
     */
    public void listenForScepCRLPathChanges(@Observes @ConfigurationChangeNotification(propertyName = "scepCRLPath") final String scepCRLPath) {
        if (scepCRLPath != null) {
            logger.debug("Configuration change listener invoked since the scepCRLPath value has got changed in the model. The new scepCRLPath is {}", scepCRLPath);
            this.scepCRLPath = scepCRLPath;
        }
    }

    /**
     * @return configuration parameter - keyStoreFilePath
     */

    public String getKeyStoreFilePath() {

        return this.keyStoreFilePath;
    }

    /**
     * @return configuration parameter - keyStoreFileType
     */

    public String getKeyStoreFileType() {
        return this.keyStoreFileType;
    }

    /**
     * @return configuration parameter - scepRequestRecordPurgePeriod
     */

    public int getScepRequestRecordPurgePeriod() {

        return this.scepRequestRecordPurgePeriod;
    }

    /**
     * @return configuration parameter - scepDBCleanupSchedulerTime
     */

    public String getScepDBCleanupSchedulerTime() {
        return this.scepDBCleanupSchedulerTime;
    }

    /**
     * @return configuration parameter - scepRAInfraCertAliasName
     */

    public String getScepRAInfraCertAliasName() {
        return this.scepRAInfraCertAliasName;
    }

    /**
     * @return configuration parameter - scepRATrustStoreFilePath
     */

    public String getScepRATrustStoreFilePath() {
        return this.scepRATrustStoreFilePath;
    }

    /**
     * @return configuration parameter - trustStoreFileType
     */

    public String getTrustStoreFileType() {
        return this.trustStoreFileType;
    }

    /**
     * @return the scepCRLPath
     */
    public String getScepCRLPath() {
        return scepCRLPath;
    }
}