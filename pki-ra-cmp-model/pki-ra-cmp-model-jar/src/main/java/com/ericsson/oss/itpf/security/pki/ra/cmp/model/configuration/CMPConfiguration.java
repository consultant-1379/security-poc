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
package com.ericsson.oss.itpf.security.pki.ra.cmp.model.configuration;

import com.ericsson.oss.itpf.modeling.annotation.DefaultValue;
import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.configparam.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class defines all the configuration parameters wrt CMPV2 service.
 * 
 * @author tcsdemi
 *
 */
@EModel(namespace = CMPModelConstants.CMP_NAMESPACE, description = "Configuration for CMP services")
@ConfParamDefinitions
public class CMPConfiguration {

    @ConfParamDefinition(description = "CRLs Location", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("/ericsson/pkira/data/crls/CMP_CRLStore")
    public String cRLPath;

    @ConfParamDefinition(description = "Alias Name to KeyStore", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("CMPRA")
    public String keyStoreAlias;

    @ConfParamDefinition(description = "Type of the key store file", scope = Scope.GLOBAL)
    @DefaultValue("PKCS12")
    public String keyStoreFileType;

    @ConfParamDefinition(description = "Path to fetch the keyStore file which is used to fetch signerCertificate and signer keypair", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("/ericsson/pkira/data/certs/CMPRAServerKeyStore.p12")
    public String keyStorePath;

    @ConfParamDefinition(description = "Type of the vendor trust store file", scope = Scope.GLOBAL)
    @DefaultValue("JKS")
    public String vendorTrustStoreFileType;

    @ConfParamDefinition(description = "Path to fetch Vendor Certificates", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("/ericsson/pkira/data/certs/CMPRAExternalTrustStore.jks")
    public String vendorCertificatesPath;

    @ConfParamDefinition(description = "Type of the ca trust store file", scope = Scope.GLOBAL)
    @DefaultValue("JKS")
    public String caTrustStoreFileType;

    @ConfParamDefinition(description = "Path to fetch CA Certificates", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("/ericsson/pkira/data/certs/CMPRAInternalTrustStore.jks")
    public String caCertificatesPath;

    @ConfParamDefinition(description = "This is the default time period until which node will wait to send pollRequest", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("60")
    public int nodeWaitTimeBeforePollRequest;

    @ConfParamDefinition(description = "This Time Out value is used in dbCleanUp Process.(to check whether currentSystem time and the modifytime is greater than requestTimeOut)", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("14")
    public int requestTimeout;

    @ConfParamDefinition(description = "Algorithm for IAK", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("1.2.840.113549.1.1.11")
    public String algorithmForIAKSigning;

    @ConfParamDefinition(description = "This parameter is used to invoke scheduler based on the given timeOut value", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,0,0,0")
    public String dbMaintenanceSchedulerInterval;

    @ConfParamDefinition(description = "Alias name for CMP ra infrastructure certificate", scope = Scope.GLOBAL)
    @DefaultValue("infrastructure_cmp_ra")
    public String cMPRAInfraCertAliasName;
}
