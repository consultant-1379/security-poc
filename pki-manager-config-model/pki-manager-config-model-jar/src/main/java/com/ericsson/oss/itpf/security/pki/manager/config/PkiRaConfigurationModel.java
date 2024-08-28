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
 * This class contains the configuration parameters related to RAService. The value of these configuration parameters can be updated using PIB.
 * 
 * scepServiceAddress, cmpServiceAddress, cdpsAddress, tdpsAddress parameters are deprecated due to the introduction of new parameters(sbLoadBalancerIPv4Address,sbLoadBalancerIPv6Address) for the IPv4
 * and IPv6 enrollment urls.
 * 
 * @author xbensar
 **/
@EModel(namespace = "pki-manager", description = "Configuration for scepServiceAddress, cmpServiceAddress, cdpsAddress,tdpAddress,sbLoadBalancerIPv4Address,publicKeyRegAutorithyPublicServerName and sbLoadBalancerIPv6Address")
@ConfParamDefinitions
public class PkiRaConfigurationModel {

    @ConfParamDefinition(description = "SCEP Service address value to provide Load balancer IPv4 URL for SCEP service", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String scepServiceAddress;

    @ConfParamDefinition(description = "CMP Service address value to provide Load balancer IPv4 URL for CMP service", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String cmpServiceAddress;

    @ConfParamDefinition(description = "CDPS Service address value to provide Load balancer IPv4 URL for CDPS service", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String cdpsAddress;

    @ConfParamDefinition(description = "TDPS Service address value to provide Load balancer IPv4 URL for TDPS service", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String tdpsAddress;

    @ConfParamDefinition(description = "Haproxysb IPv4 loadbalancer address value to provide haproxysb ip address for IPv4", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String sbLoadBalancerIPv4Address;

    @ConfParamDefinition(description = "Haproxysb IPv6 loadbalancer address value to provide haproxysb ip address for IPv6", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String sbLoadBalancerIPv6Address;

    @ConfParamDefinition(description = "PKI RA public server name", scope = Scope.GLOBAL)
    @DefaultValue("")
    public String publicKeyRegAutorithyPublicServerName;

}
