/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pkira.scep.config;

import com.ericsson.oss.itpf.modeling.annotation.DefaultValue;
import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.configparam.*;

/**
 * Scep configuration model to define configuration parameters for scep service which includes 1. KeyStoreFilePath: Key store file path. 2. KeyStoreFileType: Type of the key store file. 3.
 * SCEPRequestRecordPurgePeriod: the records which are older than or equal to this time period will be purged from the database. 4. SCEPDBCleanupSchedulerTime: the Scheduler time at which the SCEP RA
 * DB clean up scheduler will be triggered. 5. SCEPRAInfraCertAliasName: Alias name for the SCEP RA Infrastructure Certificate in the key store file. 6. ScepRATrustStoreFilePath: File path for the
 * trust store. 7. TrustStoreFileType: Type of the trust store file. 8. scepCRLPath: File path for the SCEP CRLS.
 *
 * @author xnagsow
 **/
@EModel(namespace = "pki-ra-scep", description = "Configuration for scep services")
@ConfParamDefinitions
public class ScepConfigurationModel {

    @ConfParamDefinition(description = "Relative or absolute path of the key store file", scope = Scope.GLOBAL)
    @DefaultValue("/ericsson/pkira/data/certs/SCEPRAServerKeyStore.p12")
    public String keyStoreFilePath;

    @ConfParamDefinition(description = "Type of the key store file", scope = Scope.GLOBAL)
    @DefaultValue("PKCS12")
    public String keyStoreFileType;

    @ConfParamDefinition(description = "Period of days to purge older records in DB", scope = Scope.GLOBAL)
    @DefaultValue("7")
    public int scepRequestRecordPurgePeriod;

    @ConfParamDefinition(description = "Interval time to invoke SCEP RA DB cleanup scheduler", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,0,0,0")
    public String scepDBCleanupSchedulerTime;

    @ConfParamDefinition(description = "Alias name for scep ra infrastructure certificate", scope = Scope.GLOBAL)
    @DefaultValue("infrastructure_scep_ra")
    public String scepRAInfraCertAliasName;

    @ConfParamDefinition(description = "Relative or absolute path of the trust store file", scope = Scope.GLOBAL)
    @DefaultValue("/ericsson/pkira/data/certs/SCEPRAServerTrustStore.jks")
    public String scepRATrustStoreFilePath;

    @ConfParamDefinition(description = "Type of the trust store file", scope = Scope.GLOBAL)
    @DefaultValue("JKS")
    public String trustStoreFileType;

    // This configuration parameter is deprecated and should not be used further.
    @ConfParamDefinition(description = "Interval time to invoke Scheduler", scope = Scope.GLOBAL)
    // year,month,dayOfMonth,dayOfWeek,hour,minute,second
    @DefaultValue("*,*,*,*,0,0,0")
    public String schedulerTime;

    @ConfParamDefinition(description = "SCEP CRLs Location", scope = Scope.GLOBAL, overridableInScopes = Scope.GLOBAL)
    @DefaultValue("/ericsson/pkira/data/crls/scep_crlstore")
    public String scepCRLPath;
}
