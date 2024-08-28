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
package com.ericsson.oss.itpf.security.credential.manager.config;

import com.ericsson.oss.itpf.modeling.annotation.DefaultValue;
import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.configparam.*;

/**
 * CredentialManagerConfigurationModel class contains the configuration parameter serviceCertAutoRenewalTimer, serviceCertAutoRenewalEnabled, 
 * serviceCertAutoRenewalMax, serviceCertAutoRenewalWarnings.
 * used in the CertificateReissueAuto during the renewal of service Certificates.
 * serviceCertAutoRenewalTimer - used to trigger status update scheduler. 
 * serviceCertAutoRenewalEnabled - used to enable the autorenewal feature. 
 * serviceCertAutoRenewalWarnings - used to trigger warnings notification scheduler. 
 * The value of these configuration parameters can be update using PIB.
 *
 * @author elucspo, emedmar, efilgal
 **/

@EModel(namespace = "credential-manager", description = "Configuration for autorenewal certificate for credential-manager-service, Configuration for autorenewal certificate for node-security")
@ConfParamDefinitions
public class CredentialManagerConfigurationModel {
    @ConfParamDefinition(description = "serviceCertAutoRenewalTimer value (day)to trigger the certificate autorenewal", scope = Scope.GLOBAL)
    @DefaultValue("2")
    public int serviceCertAutoRenewalTimer;

    @ConfParamDefinition(description = "serviceCertAutoRenewalEnabled value to enable the autorenewal feature", scope = Scope.GLOBAL)
    @DefaultValue("true")
    public boolean serviceCertAutoRenewalEnabled;

    @ConfParamDefinition(description = "serviceCertAutoRenewalWarnings values to trigger the warning for certificate autorenewal", scope = Scope.GLOBAL)
    @DefaultValue("20,10,5")
    public String serviceCertAutoRenewalWarnings;
}
