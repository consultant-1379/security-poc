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
package com.ericsson.oss.itpf.security.credmservice.configuration.listener;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.modeling.annotation.constraints.NotNull;
import com.ericsson.oss.itpf.sdk.config.annotation.ConfigurationChangeNotification;
import com.ericsson.oss.itpf.sdk.config.annotation.Configured;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;

/**
 * 
 * This class fetch the property value of configuration parameters -loadBalancerAddress, statusUpdateSchedulerTime, fetchLatestCRLsSchedulerTime from config-model and listen for any change in the
 * configuration environment to update with new value.
 *
 * @author xnagsow
 */
@ApplicationScoped
@Profiled
public class CredentialManagerConfigurationListener {
    @Inject
    @NotNull
    @Configured(propertyName = "serviceCertAutoRenewalTimer")
    private int serviceCertAutoRenewalTimer;

    @Inject
    @NotNull
    @Configured(propertyName = "serviceCertAutoRenewalEnabled")
    private boolean serviceCertAutoRenewalEnabled;

    @Inject
    @NotNull
    @Configured(propertyName = "serviceCertAutoRenewalWarnings")
    private String serviceCertAutoRenewalWarnings;

    @Inject
    private Logger logger;

    public void listenForServiceCertAutoRenewalTimer(@Observes @ConfigurationChangeNotification(propertyName = "serviceCertAutoRenewalTimer") final int serviceCertAutoRenewalTimer) {

        logger.info("listenForServiceCertAutoRenewalTimer invoked");
        if (serviceCertAutoRenewalTimer > 0) {
            logger.debug("Configuration change listener invoked since the serviceCertAutoRenewalTimer value has got changed in the model.The new serviceCertAutoRenewalTimer is {}",
                    serviceCertAutoRenewalTimer);
                this.serviceCertAutoRenewalTimer = serviceCertAutoRenewalTimer;
        }

    }

    /**
     * This method is responsible to listen to sfwk PIB configuration parameter and to store it.
     * 
     * @param event
     *            - the event to process
     */
    public void listenForServiceCertAutoRenewalEnabled(@Observes @ConfigurationChangeNotification(propertyName = "serviceCertAutoRenewalEnabled") final boolean serviceCertAutoRenewalEnabled) {

        logger.info("listenForServiceCertAutoRenewalEnabled invoked");
            logger.debug("Configuration change listener invoked since the serviceCertAutoRenewalEnabled value has got changed in the model.The new serviceCertAutoRenewalEnabled is {}",
                    serviceCertAutoRenewalEnabled);
            this.serviceCertAutoRenewalEnabled = serviceCertAutoRenewalEnabled;

    }

    /**
     * This method is responsible to listen to sfwk PIB configuration parameter and to store it.
     * 
     * @param event
     *            - the event to process
     */
    public void listenForServiceCertAutoRenewalWarnings(@Observes @ConfigurationChangeNotification(propertyName = "serviceCertAutoRenewalWarnings") final String serviceCertAutoRenewalWarnings) {

        logger.info("listenForServiceCertAutoRenewalWarnings invoked");
        if (serviceCertAutoRenewalWarnings != null) {
            logger.debug("Configuration change listener invoked since the serviceCertAutoRenewalWarnings value has got changed in the model.The new serviceCertAutoRenewalWarnings is {}",
                    serviceCertAutoRenewalWarnings);
            this.serviceCertAutoRenewalWarnings = serviceCertAutoRenewalWarnings;
        }

    }

    /**
     * This method returns the serviceCertAutoRenewalTimer fetched from credential-manager-config-model.
     * 
     * @return serviceCertAutoRenewalTimer
     * 
     */

    public int getPibServiceCertAutoRenewalTimer() {
        logger.info("serviceCertAutoRenewalTimer: return value {}", this.serviceCertAutoRenewalTimer);
        return this.serviceCertAutoRenewalTimer;
    }

    /**
     * This method returns the serviceCertAutoRenewalEnabled fetched from credential-manager-config-model.
     * 
     * @return serviceCertAutoRenewalEnabled
     * 
     */

    public boolean getPibServiceCertAutoRenewalEnabled() {
        logger.info("serviceCertAutoRenewalEnabled: return value {}", this.serviceCertAutoRenewalEnabled);
        return this.serviceCertAutoRenewalEnabled;
    }

    /**
     * This method returns the serviceCertAutoRenewalMax fetched from credential-manager-config-model.
     * 
     * @return serviceCertAutoRenewalWarnings
     * 
     */

    public String getPibServiceCertAutoRenewalWarnings() {
        logger.info("serviceCertAutoRenewalWarnings: return value {}", this.serviceCertAutoRenewalWarnings);
        return this.serviceCertAutoRenewalWarnings;
    }

    public CredentialManagerPIBParameters getPibServiceParams() {
        final CredentialManagerPIBParameters configParam = new CredentialManagerPIBParameters();
        
        configParam.setServiceCertAutoRenewalEnabled(this.serviceCertAutoRenewalEnabled);
        configParam.setServiceCertAutoRenewalTimer(this.serviceCertAutoRenewalTimer);
        configParam.setServiceCertAutoRenewalWarnings(this.serviceCertAutoRenewalWarnings);

        return configParam;
        
    }
        

}
