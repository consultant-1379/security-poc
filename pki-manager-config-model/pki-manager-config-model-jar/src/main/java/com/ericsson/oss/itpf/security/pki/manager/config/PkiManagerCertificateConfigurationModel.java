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
 * This class contains configuration parameters to enable IPV4/IPV6 address in CDPS(CRL(Certification Revocation List) DistributionPointService) Extension of a certificate.The value of these
 * configuration parameters can be updated using PIB.
 * 
 * @author tcsramc
 *
 */
@EModel(namespace = "pki-manager", description = "Configuration for certificatesRevListDistributionPointServiceIpv4Enable,certificatesRevListDistributionPointServiceIpv6Enable, certificatesRevListDistributionPointServiceDnsEnable")
@ConfParamDefinitions
public class PkiManagerCertificateConfigurationModel {

    @ConfParamDefinition(description = "This parameter is to tell whether to add the CDPS extension in the certificate whose value contains IPv4 address", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String certificatesRevListDistributionPointServiceIpv4Enable;

    @ConfParamDefinition(description = "This parameter is to tell whether to add the CDPS extension in the certificate whose value contains IPv6 address", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String certificatesRevListDistributionPointServiceIpv6Enable;

    @ConfParamDefinition(description = " This parameter is to tell whether to add the CDPS extension in the certificate whose value contains DNS as address", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String certificatesRevListDistributionPointServiceDnsEnable;

}
