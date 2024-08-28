/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.config;

import com.ericsson.oss.itpf.modeling.annotation.DefaultValue;
import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.configparam.*;

/**
 * This class contains configuration parameters related to otpValidationPeriod and CaCertExpiryNotificationPeriod.The value of these configuration parameters can be updated using PIB.
 * 
 * @author tcsramc
 *
 */
@EModel(namespace = "pki-manager", description = "Configuration for defaultOtpValidityPeriod, caCertExpiryNotifyPeriod")
@ConfParamDefinitions
public class PkiManagerConfigurationModel {

    @ConfParamDefinition(description = "OTP Validity period for a node", scope = Scope.GLOBAL)
    @DefaultValue("30")
    public int defaultOtpValidityPeriod;

    @ConfParamDefinition(description = "Notification period value in days to trigger ca certificate expiry notification event", scope = Scope.GLOBAL)
    @DefaultValue("30")
    public String caCertExpiryNotifyPeriod;
}
