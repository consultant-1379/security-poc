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
package com.ericsson.oss.itpf.security.pki.manager.configuration.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.modeling.annotation.constraints.NotNull;
import com.ericsson.oss.itpf.sdk.config.annotation.ConfigurationChangeNotification;
import com.ericsson.oss.itpf.sdk.config.annotation.Configured;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;

/**
 * 
 * This class is used fetch the property value of configuration parameters - statusUpdateSchedulerTime, fetchLatestCRLsSchedulerTime, scepServiceAddress, cmpServiceAddress, cdpsAddress, tdpsAddress ,
 * sbLoadBalancerIPv4Address and sbLoadBalancerIPv6Address from config-model and listen for any change in the configuration environment to update with new value.
 * 
 * @author xnagsow
 */

// TODO TORF-102504 -decoupling the configuration injection and listening ConfigurationChangeNotification.

@ApplicationScoped
@Profiled
public class PKIManagerConfigurationListener {

    @Inject
    @NotNull
    @Configured(propertyName = "statusUpdateSchedulerTime")
    private String statusUpdateSchedulerTime;

    @Inject
    @NotNull
    @Configured(propertyName = "fetchLatestCRLsSchedulerTime")
    private String fetchLatestCRLsSchedulerTime;

    @Inject
    @NotNull
    @Configured(propertyName = "scepServiceAddress")
    private String scepServiceAddress;

    @Inject
    @NotNull
    @Configured(propertyName = "cmpServiceAddress")
    private String cmpServiceAddress;

    @Inject
    @NotNull
    @Configured(propertyName = "cdpsAddress")
    private String cdpsAddress;

    @Inject
    @NotNull
    @Configured(propertyName = "tdpsAddress")
    private String tdpsAddress;

    @Inject
    @NotNull
    @Configured(propertyName = "caCertExpiryNotifySchedulerTime")
    private String caCertExpiryNotifySchedulerTime;

    @Inject
    @NotNull
    @Configured(propertyName = "entityCertExpiryNotifySchedulerTime")
    private String entityCertExpiryNotifySchedulerTime;

    @Inject
    @NotNull
    @Configured(propertyName = "pkiManagerCredentialsManagementSchedulerTime")
    private String pkiManagerCredentialsManagementSchedulerTime;

    @Inject
    @NotNull
    @Configured(propertyName = "sbLoadBalancerIPv4Address")
    private String sbLoadBalancerIPv4Address;

    @Inject
    @NotNull
    @Configured(propertyName = "sbLoadBalancerIPv6Address")
    private String sbLoadBalancerIPv6Address;

    @Inject
    @NotNull
    @Configured(propertyName = "defaultOtpValidityPeriod")
    private int defaultOtpValidityPeriod;

    /*
     * Following 4 parameters have been added in order to manage in the correct way CRL URL
     */

    @Inject
    @NotNull
    @Configured(propertyName = "certificatesRevListDistributionPointServiceIpv4Enable")
    private String certificatesRevListDistributionPointServiceIpv4Enable;

    @Inject
    @NotNull
    @Configured(propertyName = "certificatesRevListDistributionPointServiceIpv6Enable")
    private String certificatesRevListDistributionPointServiceIpv6Enable;

    @Inject
    @NotNull
    @Configured(propertyName = "certificatesRevListDistributionPointServiceDnsEnable")
    private String certificatesRevListDistributionPointServiceDnsEnable;

    @Inject
    @NotNull
    @Configured(propertyName = "publicKeyRegAutorithyPublicServerName")
    private String publicKeyRegAutorithyPublicServerName;

    @Inject
    @NotNull
    @Configured(propertyName = "externalCACRLsSchedulerTime")
    private String externalCACRLsSchedulerTime;

    @Inject
    private Logger logger;

    /**
     * This method is used to listen any changes occurred in configuration environment and update the default values with the new values for the changed properties.
     *
     * @param changedConfigEnvironment
     *            This parameter is used to listen the scepServiceAddress from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.scepServiceAddress is to be changed with the new value.
     */

    public void listenForSCEPServiceAddressConfigurationChanges(@Observes @ConfigurationChangeNotification(propertyName = "scepServiceAddress") final String scepServiceAddress) {
        logger.info("listenForSCEPServiceAddressConfigurationChanges: with value {}", scepServiceAddress);
        if (scepServiceAddress != null) {
            logger.debug("Configuration change listener invoked since the scepServiceAddress value has got changed in the model. The new scepServiceAddress is {}", scepServiceAddress);
            this.scepServiceAddress = scepServiceAddress;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment and update the default values with the new values for the changed properties.
     * 
     * @param changedConfigEnvironment
     *            This parameter is used to listen the cmpServiceAddress from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.cmpServiceAddress is to be changed with the new value.
     */

    public void listenForCMPServiceAddressConfigurationChanges(@Observes @ConfigurationChangeNotification(propertyName = "cmpServiceAddress") final String cmpServiceAddress) {
        logger.info("listenForCMPServiceAddressConfigurationChanges: with value {}", cmpServiceAddress);
        if (cmpServiceAddress != null) {
            logger.debug("Configuration change listener invoked since the cmpServiceAddress value has got changed in the model. The new cmpServiceAddress is {}", cmpServiceAddress);
            this.cmpServiceAddress = cmpServiceAddress;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment and update the default values with the new values for the changed properties.
     *
     * @param changedConfigEnvironment
     *            This parameter is used to listen the cdpsAddress from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.cdpsAddress is to be changed with the new value.
     */

    public void listenForCDPSServiceAddressConfigurationChanges(@Observes @ConfigurationChangeNotification(propertyName = "cdpsAddress") final String cdpsAddress) {
        logger.info("listenForCDPSServiceAddressConfigurationChanges: with value {}", cdpsAddress);
        if (cdpsAddress != null) {
            logger.debug("Configuration change listener invoked since the cdpsAddress value has got changed in the model. The new cdpsAddress is {}", cdpsAddress);
            this.cdpsAddress = cdpsAddress;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment and update the default values with the new values for the changed properties.
     *
     * @param changedConfigEnvironment
     *            This parameter is used to listen the tdpsAddress from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.tdpsAddress is to be changed with the new value.
     */

    public void listenForTDPSServiceAddressConfigurationChanges(@Observes @ConfigurationChangeNotification(propertyName = "tdpsAddress") final String tdpsAddress) {
        logger.info("listenForTDPSServiceAddressConfigurationChanges: with value {}", tdpsAddress);
        if (tdpsAddress != null) {
            logger.debug("Configuration change listener invoked since the tdpsAddress value has got changed in the model. The new tdpsAddress is {}", tdpsAddress);
            this.tdpsAddress = tdpsAddress;
        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property sbLoadBalancerIPv4Address and update the default value with the new value for the changed
     * property.
     *
     * @param sbLoadBalancerIPv4Address
     *            This parameter is used to listen the sbLoadBalancerIPv4Address from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.sbLoadBalancerIPv4Address is to be changed with the new value.
     */

    public void listenForSbLoadBalancerIPv4AddressConfigurationChanges(@Observes @ConfigurationChangeNotification(propertyName = "sbLoadBalancerIPv4Address") final String sbLoadBalancerIPv4Address) {

        logger.info("listenForSbLoadBalancerIPV4AddressConfigurationChanges invoked");

        if (sbLoadBalancerIPv4Address != null) {
            logger.debug("Configuration change listener invoked since the sbLoadBalancerIPv4Address value has got changed in the model. The new sbLoadBalancerIPv4Address is {}",
                    sbLoadBalancerIPv4Address);
            this.sbLoadBalancerIPv4Address = sbLoadBalancerIPv4Address;

        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property sbLoadBalancerIPv6Address and update the default value with the new value for the changed
     * property.
     * 
     * @param sbLoadBalancerIPv6Address
     *            This parameter is used to listen the sbLoadBalancerIPv6Address from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.sbLoadBalancerIPv6Address is to be changed with the new value.
     */

    public void listenForSbLoadBalancerIPV6AddressConfigurationChanges(@Observes @ConfigurationChangeNotification(propertyName = "sbLoadBalancerIPv6Address") final String sbLoadBalancerIPv6Address) {

        logger.info("listenForSbLoadBalancerIPV6AddressConfigurationChanges invoked");

        if (sbLoadBalancerIPv6Address != null) {
            logger.debug("Configuration change listener invoked since the sbLoadBalancerIPv6Address value has got changed in the model. The new sbLoadBalancerIPv6Address is {}",
                    sbLoadBalancerIPv6Address);
            this.sbLoadBalancerIPv6Address = sbLoadBalancerIPv6Address;

        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property defaultOtpValidityPeriod and update the default value with the new value for the changed
     * property.
     * 
     * @param defaultOtpValidityPeriod
     *            This parameter is used to listen the defaultOtpValidityPeriod from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and the value of
     *            this.defaultOtpValidityPeriod is to be changed with the new value.
     */

    public void listenForDefaultOtpValidityPeriodConfigurationChanges(@Observes @ConfigurationChangeNotification(propertyName = "defaultOtpValidityPeriod") final int defaultOtpValidityPeriod) {

        logger.info("listenForDefaultOtpValidityPeriodConfigurationChanges invoked");

        if (defaultOtpValidityPeriod != 0) {
            logger.debug("Configuration change listener invoked since the defaultOtpValidityPeriod value has got changed in the model. The new defaultOtpValidityPeriod is {}",
                    defaultOtpValidityPeriod);
            this.defaultOtpValidityPeriod = defaultOtpValidityPeriod;

        }
        logger.info("defaultOtpValidityPeriod value got updated");
    }

    /*
     * Following 4 parameters have been added in order to manage in the correct way CRL URL
     */

    /**
     * This method is used to listen any changes occurred in configuration environment for the property certificatesRevListDistributionPointServiceIpv4Enable and update the default value with the new
     * value for the changed property.
     *
     * @param listenForcertificateCpdsIpv4ConfigurationChanges
     *            This parameter is used to listen the listenForcertificateCpdsIpv4ConfigurationChanges from the pki-manager-config-model. Whenever the value changes, it has to be listened by this
     *            parameter and the value of this.listenForcertificateCpdsIpv4ConfigurationChanges is to be changed with the new value.
     */

    public void listenForCertificateCpdsIpv4EnableConfigurationChanges(
            @Observes @ConfigurationChangeNotification(propertyName = "certificatesRevListDistributionPointServiceIpv4Enable") final String certificatesRevListDistributionPointServiceIpv4Enable) {

        logger.info("listenForcertificateCpdsIpv4ConfigurationChanges invoked");

        if (certificatesRevListDistributionPointServiceIpv4Enable != null) {
            logger.info("Configuration change listener invoked since the certificatesRevListDistributionPointServiceIpv4Enable value has got changed in the model. The new certificateCpdsIpv4 is {}",
                    certificatesRevListDistributionPointServiceIpv4Enable);
            this.certificatesRevListDistributionPointServiceIpv4Enable = certificatesRevListDistributionPointServiceIpv4Enable;

        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property certificatesRevListDistributionPointServiceIpv6Enable and update the default value with the new
     * value for the changed property.
     *
     * @param listenForcertificateCpdsIpv4ConfigurationChanges
     *            This parameter is used to listen the listenForcertificateCpdsIpv6ConfigurationChanges from the pki-manager-config-model. Whenever the value changes, it has to be listened by this
     *            parameter and the value of this.listenForcertificateCpdsIpv4ConfigurationChanges is to be changed with the new value.
     */

    public void listenForCertificateCpdsIpv6EnableConfigurationChanges(
            @Observes @ConfigurationChangeNotification(propertyName = "certificatesRevListDistributionPointServiceIpv6Enable") final String certificatesRevListDistributionPointServiceIpv6Enable) {

        logger.info("listenForcertificateCpdsIpv6ConfigurationChanges invoked");

        if (certificatesRevListDistributionPointServiceIpv6Enable != null) {
            logger.info("Configuration change listener invoked since the certificatesRevListDistributionPointServiceIpv6Enable value has got changed in the model. The new certificateCpdsIpv4 is {}",
                    certificatesRevListDistributionPointServiceIpv6Enable);
            this.certificatesRevListDistributionPointServiceIpv6Enable = certificatesRevListDistributionPointServiceIpv6Enable;

        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property certificatesRevListDistributionPointServiceDnsEnable and update the default value with the new
     * value for the changed property.
     *
     * @param listenForcertificateCpdsIpv4ConfigurationChanges
     *            This parameter is used to listen the listenForcertificateCpdsIpv6ConfigurationChanges from the pki-manager-config-model. Whenever the value changes, it has to be listened by this
     *            parameter and the value of this.listenForcertificateCpdsIpv4ConfigurationChanges is to be changed with the new value.
     */

    public void listenForCertificateCpdsDnsEnableConfigurationChanges(
            @Observes @ConfigurationChangeNotification(propertyName = "certificatesRevListDistributionPointServiceDnsEnable") final String certificatesRevListDistributionPointServiceDnsEnable) {

        logger.info("listenForcertificateCpdsDnsConfigurationChanges invoked");

        if (certificatesRevListDistributionPointServiceDnsEnable != null) {
            logger.info("Configuration change listener invoked since the certificatesRevListDistributionPointServiceDnsEnable value has got changed in the model. The new certificateCpdsIpv4 is {}",
                    certificatesRevListDistributionPointServiceDnsEnable);
            this.certificatesRevListDistributionPointServiceDnsEnable = certificatesRevListDistributionPointServiceDnsEnable;

        }
    }

    /**
     * This method is used to listen any changes occurred in configuration environment for the property sbLoadBalancerIPv4Address and update the default value with the new value for the changed
     * property.
     *
     * @param publicKeyRegAutorithyPublicServerName
     *            This parameter is used to listen the publicKeyRegAutorithyPublicServerName from the pki-manager-config-model. Whenever the value changes, it has to be listened by this parameter and
     *            the value of this.publicKeyRegAutorithyPublicServerName is to be changed with the new value.
     */

    public void listenForPKIRAPublicServerNameConfigurationChanges(
            @Observes @ConfigurationChangeNotification(propertyName = "publicKeyRegAutorithyPublicServerName") final String publicKeyRegAutorithyPublicServerName) {

        logger.info("listenForPKIRAPublicServerNameConfigurationChanges invoked");

        if (publicKeyRegAutorithyPublicServerName != null) {
            logger.info("Configuration change listener invoked since the publicKeyInfraRegAutorithyPublicServerName value has got changed in the model. The new sbLoadBalancerIPv4Address is {}",
                    publicKeyRegAutorithyPublicServerName);
            this.publicKeyRegAutorithyPublicServerName = publicKeyRegAutorithyPublicServerName;

        }
    }

    /**
     * @return the certificatesRevListDistributionPointServiceIpv4Enable
     */
    public String getCertificatesRevListDistributionPointServiceIpv4Enable() {
        return certificatesRevListDistributionPointServiceIpv4Enable;
    }

    /**
     * @param certificatesRevListDistributionPointServiceIpv4Enable
     *            the certificatesRevListDistributionPointServiceIpv4Enable to set
     */
    public void setCertificatesRevListDistributionPointServiceIpv4Enable(final String certificatesRevListDistributionPointServiceIpv4Enable) {
        this.certificatesRevListDistributionPointServiceIpv4Enable = certificatesRevListDistributionPointServiceIpv4Enable;
    }

    /**
     * @return the certificatesRevListDistributionPointServiceIpv6Enable
     */
    public String getCertificatesRevListDistributionPointServiceIpv6Enable() {
        return certificatesRevListDistributionPointServiceIpv6Enable;
    }

    /**
     * @param certificatesRevListDistributionPointServiceIpv6Enable
     *            the certificatesRevListDistributionPointServiceIpv6Enable to set
     */
    public void setCertificatesRevListDistributionPointServiceIpv6Enable(final String certificatesRevListDistributionPointServiceIpv6Enable) {
        this.certificatesRevListDistributionPointServiceIpv6Enable = certificatesRevListDistributionPointServiceIpv6Enable;
    }

    /**
     * @return the certificatesRevListDistributionPointServiceDnsEnable
     */
    public String getCertificatesRevListDistributionPointServiceDnsEnable() {
        return certificatesRevListDistributionPointServiceDnsEnable;
    }

    /**
     * @param certificatesRevListDistributionPointServiceDnsEnable
     *            the certificatesRevListDistributionPointServiceDnsEnable to set
     */
    public void setCertificatesRevListDistributionPointServiceDnsEnable(final String certificatesRevListDistributionPointServiceDnsEnable) {
        this.certificatesRevListDistributionPointServiceDnsEnable = certificatesRevListDistributionPointServiceDnsEnable;
    }

    /**
     * @return the publicKeyRegAutorithyPublicServerName
     */
    public String getPublicKeyRegAutorithyPublicServerName() {
        return publicKeyRegAutorithyPublicServerName;
    }

    /**
     * @param publicKeyRegAutorithyPublicServerName
     *            the publicKeyInfraRegAutorithyPublicServerName to set
     */
    public void setPublicKeyRegAutorithyPublicServerName(final String publicKeyRegAutorithyPublicServerName) {
        this.publicKeyRegAutorithyPublicServerName = publicKeyRegAutorithyPublicServerName;
    }

    /**
     * This method returns the statusUpdateTime fetched from pki-manager-config-model.
     * 
     * @return configuration parameter - statusUpdateTime
     */

    public String getStatusUpdateSchedulerTime() {
        return this.statusUpdateSchedulerTime;
    }

    /**
     * @param statusUpdateSchedulerTime
     *            the statusUpdateSchedulerTime to set
     */
    public void setStatusUpdateSchedulerTime(final String statusUpdateSchedulerTime) {
        this.statusUpdateSchedulerTime = statusUpdateSchedulerTime;
    }

    /**
     * This method returns the fetchLatestCRLsSchedulerTime fetched from pki-manager-config-model.
     * 
     * @return configuration parameter - fetchLatestCRLsSchedulerTime
     */

    public String getFetchLatestCRLsSchedulerTime() {
        return this.fetchLatestCRLsSchedulerTime;
    }

    /**
     * @param fetchLatestCRLsSchedulerTime
     *            the fetchLatestCRLsSchedulerTime to set
     */
    public void setFetchLatestCRLsSchedulerTime(final String fetchLatestCRLsSchedulerTime) {
        this.fetchLatestCRLsSchedulerTime = fetchLatestCRLsSchedulerTime;
    }

    /**
     * This method returns the scepServiceAddress fetched from pki-manager-config-model.
     *
     * @return the scepServiceAddress
     */
    public String getScepServiceAddress() {
        logger.info("getScepServiceAddress: return value {}", this.scepServiceAddress);
        return this.scepServiceAddress;
    }

    /**
     * This method returns the cmpServiceAddress fetched from pki-manager-config-model.
     *
     * @return the cmpServiceAddress
     */
    public String getCmpServiceAddress() {
        logger.info("getCmpServiceAddress: return value {}", this.cmpServiceAddress);
        return this.cmpServiceAddress;
    }

    /**
     * This method returns the cdpsAddress fetched from pki-manager-config-model.
     *
     * @return the cdpsAddress
     */
    public String getCdpsAddress() {
        logger.info("getCdpsAddress: return value {}", this.cdpsAddress);
        return this.cdpsAddress;
    }

    /**
     * This method returns the tdpsAddress fetched from pki-manager-config-model.
     *
     * @return the tdpsAddress
     */
    public String getTdpsAddress() {
        logger.info("getTdpsAddress: return value {}", this.tdpsAddress);
        return this.tdpsAddress;
    }

    /**
     * This method returns the pkiManagerCredentialsManagementSchedulerTime fetched from pki-manager-config-model.
     *
     * @return the pkiManagerCredentialsManagementSchedulerTime
     */
    public String getPkiManagerCredentialsManagementSchedulerTime() {
        return pkiManagerCredentialsManagementSchedulerTime;
    }

    /**
     * @param pkiManagerCredentialsManagementSchedulerTime
     *            the pkiManagerCredentialsManagementSchedulerTime to set
     */
    public void setPkiManagerCredentialsManagementSchedulerTime(final String pkiManagerCredentialsManagementSchedulerTime) {
        this.pkiManagerCredentialsManagementSchedulerTime = pkiManagerCredentialsManagementSchedulerTime;
    }

    /**
     * This method returns the sbLoadBalancerIPv4Address fetched from pki-manager-config-model.
     *
     * @return the sbLoadBalancerIPv4Address
     */
    public String getSbLoadBalancerIPv4Address() {
        logger.debug("getSbLoadBalancerIPv4Address: return value {}", this.sbLoadBalancerIPv4Address);
        return sbLoadBalancerIPv4Address;
    }

    /**
     * This method returns the sbLoadBalancerIPv6Address fetched from pki-manager-config-model.
     *
     * @return the sbLoadBalancerIPv6Address
     */
    public String getSbLoadBalancerIPv6Address() {
        logger.debug("getSbLoadBalancerIPv6Address: return value {}", this.sbLoadBalancerIPv6Address);
        return sbLoadBalancerIPv6Address;
    }

    /**
     * @param caCertExpiryNotifySchedulerTime
     *            the caCertExpiryNotifySchedulerTime to set
     */
    public void setCaCertExpiryNotifySchedulerTime(final String caCertExpiryNotifySchedulerTime) {
        this.caCertExpiryNotifySchedulerTime = caCertExpiryNotifySchedulerTime;
    }

    /**
     * @param entityCertExpiryNotifySchedulerTime
     *            the entityCertExpiryNotifySchedulerTime to set
     */
    public void setEntityCertExpiryNotifySchedulerTime(final String entityCertExpiryNotifySchedulerTime) {
        this.entityCertExpiryNotifySchedulerTime = entityCertExpiryNotifySchedulerTime;
    }

    /**
     * This method returns the caCertExpiryNotifySchedulerTime fetched from pki-manager-config-model.
     *
     * @return the caCertExpiryNotifySchedulerTime
     */
    public String getCaCertExpiryNotifySchedulerTime() {
        logger.info("getCaCertExpiryNotifySchedulerTime: return value {}", this.caCertExpiryNotifySchedulerTime);
        return this.caCertExpiryNotifySchedulerTime;
    }

    /**
     * This method returns the entityCertExpiryNotifySchedulerTime fetched from pki-manager-config-model.
     *
     * @return the entityCertExpiryNotifySchedulerTime
     */
    public String getEntityCertExpiryNotifySchedulerTime() {
        logger.info("getEntityCertExpiryNotifySchedulerTime: return value {}", this.entityCertExpiryNotifySchedulerTime);
        return this.entityCertExpiryNotifySchedulerTime;
    }

    /**
     * This method returns the externalCACRLsSchedulerTime fetched from pki-manager-config-model.
     *
     * @return the externalCACRLsSchedulerTime
     */
    public String getExternalCACRLsSchedulerTime() {
        return externalCACRLsSchedulerTime;
    }

    /**
     * @param externalCACRLsSchedulerTime
     *            the externalCACRLsSchedulerTime to set
     */
    public void setExternalCACRLsSchedulerTime(final String externalCACRLsSchedulerTime) {
        this.externalCACRLsSchedulerTime = externalCACRLsSchedulerTime;
    }

    /**
     * @return the defaultOtpValidityPeriod
     */
    public int getDefaultOtpValidityPeriod() {
        return defaultOtpValidityPeriod;
    }

}
