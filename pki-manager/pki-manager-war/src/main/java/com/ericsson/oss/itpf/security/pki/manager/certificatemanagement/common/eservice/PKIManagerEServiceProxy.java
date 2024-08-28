/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.*;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.TAFEntityManagementServiceLocal;

@ApplicationScoped
public class PKIManagerEServiceProxy {

    @EServiceRef
    private ProfileManagementService profileManagementService;

    @EServiceRef
    EntityCertificateManagementService entityCertificateManagementService;

    @EServiceRef
    private CACertificateManagementService caCertificateManagementService;

    @EServiceRef
    RevocationService revocationService;

    @EServiceRef
    private EntityManagementService entityManagementService;

    @EServiceRef
    private PKIConfigurationManagementService pkiConfigurationManagementService;

    @EServiceRef
    ExtCACRLManagementService extCACRLManagementService;

    @EServiceRef
    ExtCACertificateManagementService extCaCertificateManagementService;

    @EServiceRef
    private TAFEntityManagementServiceLocal tafEntityManagementService;

    public ProfileManagementService getProfileManagementService() {
        return profileManagementService;
    }

    public EntityCertificateManagementService getEntityCertificateManagementService() {
        return entityCertificateManagementService;
    }

    public CACertificateManagementService getCaCertificateManagementService() {
        return caCertificateManagementService;
    }

    public RevocationService getRevocationService() {
        return revocationService;
    }

    public EntityManagementService getEntityManagementService() {
        return entityManagementService;
    }

    public PKIConfigurationManagementService getPkiConfigurationManagementService() {
        return pkiConfigurationManagementService;
    }

    public ExtCACRLManagementService getExtCACRLManagementService() {
        return extCACRLManagementService;
    }

    public ExtCACertificateManagementService getExtCaCertificateManagementService() {
        return extCaCertificateManagementService;
    }

    public TAFEntityManagementServiceLocal getTafEntityManagementService() {
        return tafEntityManagementService;
    }

}
