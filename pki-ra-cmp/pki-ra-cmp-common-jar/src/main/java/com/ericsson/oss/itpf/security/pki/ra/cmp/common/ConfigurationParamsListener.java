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

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.modeling.annotation.constraints.NotNull;
import com.ericsson.oss.itpf.sdk.config.annotation.ConfigurationChangeNotification;
import com.ericsson.oss.itpf.sdk.config.annotation.Configured;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;

/**
 * This class defines Listeners/getters/setters for CMP Configuration parameters. These parameters are ModeledConfiguration parameters which will send out PIB notifications on any modification. This
 * class has listners for these notifications.
 * 
 * @author tcsdemi
 *
 */
@ApplicationScoped
public class ConfigurationParamsListener {
    @Inject
    Logger logger;

    @Inject
    @NotNull
    @Configured(propertyName = "nodeWaitTimeBeforePollRequest")
    private int nodeWaitTimeBeforePollRequest;

    @Inject
    @NotNull
    @Configured(propertyName = "requestTimeout")
    private int requestTimeout;

    @Inject
    @NotNull
    @Configured(propertyName = "algorithmForIAKSigning")
    private String algorithmForIAKSigning;

    @Inject
    @NotNull
    @Configured(propertyName = "keyStoreAlias")
    private String keyStorealias;

    @Inject
    @NotNull
    @Configured(propertyName = "keyStoreFileType")
    private String keyStoreFileType;

    @Inject
    @NotNull
    @Configured(propertyName = "keyStorePath")
    private String keyStorePath;

    @Inject
    @NotNull
    @Configured(propertyName = "vendorTrustStoreFileType")
    private String vendorTrustStoreFileType;

    @Inject
    @NotNull
    @Configured(propertyName = "vendorCertificatesPath")
    private String vendorCertificatesPath;

    @Inject
    @NotNull
    @Configured(propertyName = "caTrustStoreFileType")
    private String caTrustStoreFileType;

    @Inject
    @NotNull
    @Configured(propertyName = "caCertificatesPath")
    private String caCertificatesPath;

    @Inject
    @NotNull
    @Configured(propertyName = "cRLPath")
    private String cRLPath;

    @Inject
    @NotNull
    @Configured(propertyName = "dbMaintenanceSchedulerInterval")
    private String dbMaintenanceSchedulerInterval;

    @Inject
    @NotNull
    @Configured(propertyName = "cMPRAInfraCertAliasName")
    private String cMPRAInfraCertAliasName;

    /**
     * This method is used to listen any changes occurred in configuration environment for the property cRLPath and update the default value with the new value for the changed property.
     * 
     * @param cRLPath
     *            This parameter is used to listen the cRLPath from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of this.cRLPath is to be
     *            changed with the new value.
     */
    public void listenForcRLPathChanges(@Observes @ConfigurationChangeNotification(propertyName = "cRLPath") final String cRLPath) {
        if (cRLPath != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", cRLPath);
            this.cRLPath = cRLPath;
        }
    }

    /**
     * Any PIB notifications for nodeWaitTimeBeforePollRequest parameter will be listened and updated as the current modelConf value.
     * 
     * @param nodeWaitTimeBeforePollRequest
     */
    public void listenForNodeWaitTimeBeforePollRequest(@Observes @ConfigurationChangeNotification(propertyName = "nodeWaitTimeBeforePollRequest") final int nodeWaitTimeBeforePollRequest) {

        if (nodeWaitTimeBeforePollRequest != 0) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}" , nodeWaitTimeBeforePollRequest);
            this.nodeWaitTimeBeforePollRequest = nodeWaitTimeBeforePollRequest;
        }
    }

    /**
     * Any PIB notifications for requestTimeout parameter will be listened and updated as the current modelConf value.
     * 
     * @param requestTimeout
     */
    public void listenForRequestTimeout(@Observes @ConfigurationChangeNotification(propertyName = "requestTimeout") final int requestTimeout) {

        if (requestTimeout != 0) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}" , requestTimeout);
            this.requestTimeout = requestTimeout;
        }
    }

    /**
     * Any PIB notifications for algorithmForIAKSigning parameter will be listened and updated as the current modelConf value.
     * 
     * @param algorithmForIAKSigning
     */
    public void listenForAlgorithmForIAKSigning(@Observes @ConfigurationChangeNotification(propertyName = "algorithmForIAKSigning") final String algorithmForIAKSigning) {

        if (algorithmForIAKSigning != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}" , algorithmForIAKSigning);
            this.algorithmForIAKSigning = algorithmForIAKSigning;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property keyStorealias and update the default value with the new value for the changed property.
     * 
     * @param keyStorealias
     *            This parameter is used to listen the keyStorealias from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of this.keyStorealias
     *            is to be changed with the new value.
     */
    public void listenForKeyStorealiasChanges(@Observes @ConfigurationChangeNotification(propertyName = "keyStorealias") final String keyStorealias) {
        if (keyStorealias != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", keyStorealias);
            this.keyStorealias = keyStorealias;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property keyStoreFileType and update the default value with the new value for the changed property.
     * 
     * @param keyStoreFileType
     *            This parameter is used to listen the keyStoreFileType from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.keyStoreFileType is to be changed with the new value.
     */
    public void listenForKeyStoreFileTypeChanges(@Observes @ConfigurationChangeNotification(propertyName = "keyStoreFileType") final String keyStoreFileType) {
        if (keyStoreFileType != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", keyStoreFileType);
            this.keyStoreFileType = keyStoreFileType;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property keyStorePath and update the default value with the new value for the changed property.
     * 
     * @param keyStorePath
     *            This parameter is used to listen the keyStorePath from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of this.keyStorePath is
     *            to be changed with the new value.
     */
    public void listenForKeyStorePathChanges(@Observes @ConfigurationChangeNotification(propertyName = "keyStorePath") final String keyStorePath) {
        if (keyStorePath != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", keyStorePath);
            this.keyStorePath = keyStorePath;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property vendorTrustStoreFileType and update the default value with the new value for the changed
     * property.
     * 
     * @param vendorTrustStoreFileType
     *            This parameter is used to listen the vendorTrustStoreFileType from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.vendorTrustStoreFileType is to be changed with the new value.
     */
    public void listenForVendorTrustStoreFileTypeChanges(@Observes @ConfigurationChangeNotification(propertyName = "vendorTrustStoreFileType") final String vendorTrustStoreFileType) {
        if (vendorTrustStoreFileType != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", vendorTrustStoreFileType);
            this.vendorTrustStoreFileType = vendorTrustStoreFileType;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property vendorCertificatesPath and update the default value with the new value for the changed property.
     * 
     * @param vendorCertificatesPath
     *            This parameter is used to listen the vendorCertificatesPath from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.vendorCertificatesPath is to be changed with the new value.
     */
    public void listenForVendorCertificatesPathChanges(@Observes @ConfigurationChangeNotification(propertyName = "vendorCertificatesPath") final String vendorCertificatesPath) {
        if (vendorCertificatesPath != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", vendorCertificatesPath);
            this.vendorCertificatesPath = vendorCertificatesPath;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property caTrustStoreFileType and update the default value with the new value for the changed property.
     * 
     * @param caTrustStoreFileType
     *            This parameter is used to listen the caTrustStoreFileType from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.caTrustStoreFileType is to be changed with the new value.
     */
    public void listenForCATrustStoreFileTypeChanges(@Observes @ConfigurationChangeNotification(propertyName = "caTrustStoreFileType") final String caTrustStoreFileType) {
        if (caTrustStoreFileType != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", caTrustStoreFileType);
            this.caTrustStoreFileType = caTrustStoreFileType;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property caCertificatesPath and update the default value with the new value for the changed property.
     * 
     * @param caCertificatesPath
     *            This parameter is used to listen the caCertificatesPath from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.caCertificatesPath is to be changed with the new value.
     */
    public void listenForCACertificatesPathChanges(@Observes @ConfigurationChangeNotification(propertyName = "caCertificatesPath") final String caCertificatesPath) {
        if (caCertificatesPath != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", caCertificatesPath);
            this.caCertificatesPath = caCertificatesPath;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property cMPRAInfraCertAliasName and update the default value with the new value for the changed
     * property.
     * 
     * @param cMPRAAliasName
     *            This parameter is used to listen the cMPRAInfraCertAliasName from the pki-ra-cmp-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.cMPRAInfraCertAliasName is to be changed with the new value.
     */
    public void listenForcMPRAInfraCertAliasName(@Observes @ConfigurationChangeNotification(propertyName = "cMPRAInfraCertAliasName") final String cMPRAAliasName) {
        if (cMPRAAliasName != null) {
            logger.info("Default  value have been replaced with new changed value for the configuration parameter {}", cMPRAAliasName);
            this.cMPRAInfraCertAliasName = cMPRAAliasName;
        }
    }

    /**
     * Sets the changed value to configuration parameter cRLPath
     * 
     * @param cRLPath
     *            value to be set
     */
    public void setCRLPath(final String cRLPath) {
        this.cRLPath = cRLPath;
    }

    /**
     * 
     * @return configuration parameter - cRLPath
     */
    @Profiled
    public String getCRLPath() {
        return this.cRLPath;
    }

    /**
     * Sets the changed alias to configuration parameter keyStorealias
     * 
     * @param alias
     *            value to be set
     * 
     */
    public void setKeyStoreAlias(final String alias) {
        this.keyStorealias = alias;
    }

    /**
     * 
     * @return configuration parameter - keyStorealias
     */
    @Profiled
    public String getKeyStoreAlias() {
        return this.keyStorealias;
    }

    /**
     * Sets the changed value to configuration parameter keyStorePath
     * 
     * @param path
     *            value to be set
     */
    public void setKeyStorePath(final String path) {
        this.keyStorePath = path;
    }

    /**
     * 
     * @return configuration parameter - keyStorePath
     */
    @Profiled
    public String getKeyStorePath() {
        return this.keyStorePath;
    }

    /**
     * 
     * @return configuration parameter - keyStoreFileType
     */
    @Profiled
    public String getKeyStoreFileType() {
        return this.keyStoreFileType;
    }

    /**
     * Sets the changed value to configuration parameter keyStoreFileType
     * 
     * @param keyStoreFileType
     *            value to be set
     */
    public void setKeyStoreFileType(final String keyStoreFileType) {
        this.keyStoreFileType = keyStoreFileType;
    }

    /**
     * Will change the current value of nodeWaitTimeBeforePollRequest to the one given as input param. Once value is set, PIB notifications will be sent out by Modelling SDK itself.
     * 
     * @param nodeWaitTimeBeforePollRequest
     */
    public void setNodeWaitTimeBeforePollRequest(final int nodeWaitTimeBeforePollRequest) {
        this.nodeWaitTimeBeforePollRequest = nodeWaitTimeBeforePollRequest;
    }

    /**
     * Will fetch the current set value of nodeWaitTimeBeforePollRequest.
     * 
     * @return
     */
    @Profiled
    public int getNodeWaitTimeBeforePollRequest() {
        return this.nodeWaitTimeBeforePollRequest;

    }

    /**
     * Will change the current value of requestTimeout to the one given as input param. Once value is set, PIB notifications will be sent out by Modelling SDK itself.
     * 
     * @param timeOut
     */
    public void setRequestTimeOut(final int timeOut) {
        this.requestTimeout = timeOut;
    }

    /**
     * Will fetch the current set value of requestTimeout.
     * 
     * @return
     */
    @Profiled
    public int getRequestTimeOut() {
        return this.requestTimeout;

    }

    /**
     * Will change the current value of algorithmForIAKSigning to the one given as input param. Once value is set, PIB notifications will be sent out by Modelling SDK itself. Input parameter should be
     * a proper OID. For eg: in the form of "1.2.840.113533.7.66.13" In case a wrong OID is given then there will be an exception thrown while Algorithms are validated.
     * 
     * @param algoIdentifier
     */

    public void setAlgorithmForIAKSigning(final String algoIdentifier) {
        this.algorithmForIAKSigning = algoIdentifier;
    }

    /**
     * Will fetch the current set value of algorithmForIAKSigning.
     * 
     * @return
     */
    @Profiled
    public String getAlgorithmForIAKSigning() {
        return this.algorithmForIAKSigning;

    }

    /**
     * Sets the changed value to configuration parameter vendorCertificatesPath
     * 
     * @param vendorCertPath
     *            value to be set
     */
    public void setVendorCertPath(final String vendorCertPath) {
        this.vendorCertificatesPath = vendorCertPath;
    }

    /**
     * 
     * @return configuration parameter - VendorCertPath
     */
    @Profiled
    public String getVendorCertPath() {
        return this.vendorCertificatesPath;
    }

    /**
     * Sets the changed value to configuration parameter vendorTrustStoreFileType
     * 
     * @param vendorTrustStoreFileType
     *            value to be set
     */
    public void setVendorTrustStoreFileType(final String vendorTrustStoreFileType) {
        this.vendorTrustStoreFileType = vendorTrustStoreFileType;
    }

    /**
     * 
     * @return configuration parameter - TrustStoreFileType
     */
    @Profiled
    public String getVendorTrustStoreFileType() {
        return this.vendorTrustStoreFileType;
    }

    /**
     * Sets the changed value to configuration parameter caCertificatesPath
     * 
     * @param caCertPath
     *            value to be set
     */
    public void setCACertPath(final String caCertPath) {
        this.caCertificatesPath = caCertPath;
    }

    /**
     * 
     * @return configuration parameter - caCertPath
     */
    @Profiled
    public String getCACertPath() {
        return this.caCertificatesPath;
    }

    /**
     * 
     * @return configuration parameter - caTrustStoreFileType
     */
    @Profiled
    public String getCATrustStoreFileType() {
        return this.caTrustStoreFileType;
    }

    /**
     * Sets the changed value to configuration parameter caTrustStoreFileType
     * 
     * @param caTrustStoreFileType
     *            value to be set
     */
    public void setCATrustStoreFileType(final String caTrustStoreFileType) {
        this.caTrustStoreFileType = caTrustStoreFileType;
    }

    /**
     * @return the dbMaintenanceSchedulerInterval
     */
    public String getDbMaintenanceSchedulerInterval() {
        return dbMaintenanceSchedulerInterval;
    }

    /**
     * @param dbMaintenanceSchedulerInterval
     *            the dbMaintenanceSchedulerInterval to set
     */
    public void setDbMaintenanceSchedulerInterval(final String dbMaintenanceSchedulerInterval) {
        this.dbMaintenanceSchedulerInterval = dbMaintenanceSchedulerInterval;
    }

    /**
     * @return the cMPRAInfraCertAliasName
     */
    public String getCMPRAInfraCertAliasName() {
        return cMPRAInfraCertAliasName;
    }

    /**
     * @param cMPRAInfraCertAliasName
     *            the cMPRAInfraCertAliasName to set
     */
    public void setCMPRAInfraCertAliasName(final String cMPRAInfraCertAliasName) {
        this.cMPRAInfraCertAliasName = cMPRAInfraCertAliasName;
    }

}
