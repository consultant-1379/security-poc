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
package com.ericsson.itpf.security.pki.cmdhandler.common;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.itpf.security.pki.web.cli.local.service.api.CSRManagementService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.custom.EntityCertificateManagementCustomService;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ExtCAManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;

@ApplicationScoped
public class EServiceRefProxy {

    @EServiceRef
    private EntityManagementService entityManagementService;

    @EServiceRef
    private ExtCACRLManagementService extCaCrlManager;

    @EServiceRef
    private ExtCACertificateManagementService extCaCertificateManagementService;

    @EServiceRef
    private ExtCAManagementService extCaManager;

    @EServiceRef
    private PKIConfigurationManagementService pkiConfigurationManagementService;

    @EServiceRef
    private EntityCertificateManagementService entityCertificateManagementService;

    @EServiceRef
    private CRLManagementService crlManagementService;

    @EServiceRef
    private ProfileManagementService profileManagementService;

    @EServiceRef
    private EntityCertificateManagementService endEntityCertificateManagementService;

    @EServiceRef
    private CACertificateManagementService caCertificateManagementService;

    @EServiceRef
    private RevocationService revocationService;

    @EServiceRef
    private ExtCACRLManagementService extCaCrlManagementService;

    @EServiceRef
    private CSRManagementService csrManagementService;

    @EServiceRef
    private ExtCAManagementService extCaManagementService;

    @EServiceRef
    private EntityCertificateManagementCustomService entityCertificateManagementCustomService;

    /**
     * @return the entityManagementService
     */
    public EntityManagementService getEntityManagementService() {
        return entityManagementService;
    }

    /**
     * @return the extCACRLManager
     */
    public ExtCACRLManagementService getExtCaCrlManager() {
        return extCaCrlManager;
    }

    /**
     * @return the extCaCertificateManagementService
     */
    public ExtCACertificateManagementService getExtCaCertificateManagementService() {
        return extCaCertificateManagementService;
    }

    /**
     * @return the extCAmanager
     */
    public ExtCAManagementService getExtCaManager() {
        return extCaManager;
    }

    /**
     * @return the pkiConfigurationManagementService
     */
    public PKIConfigurationManagementService getPkiConfigurationManagementService() {
        return pkiConfigurationManagementService;
    }

    /**
     * @return the entityCertificateManagementService
     */
    public EntityCertificateManagementService getEntityCertificateManagementService() {
        return entityCertificateManagementService;
    }

    /**
     * @return the cRLManagementService
     */
    public CRLManagementService getCrlManagementService() {
        return crlManagementService;
    }

    /**
     * @return the profileManagementService
     */
    public ProfileManagementService getProfileManagementService() {
        return profileManagementService;
    }

    /**
     * @return the endEntityCertificateManagementService
     */
    public EntityCertificateManagementService getEndEntityCertificateManagementService() {
        return endEntityCertificateManagementService;
    }

    /**
     * @return the caCertificateManagementService
     */
    public CACertificateManagementService getCaCertificateManagementService() {
        return caCertificateManagementService;
    }

    /**
     * @return the revocationService
     */
    public RevocationService getRevocationService() {
        return revocationService;
    }

    /**
     * @return the extCaCrlManagementService
     */
    public ExtCACRLManagementService getExtCaCrlManagementService() {
        return extCaCrlManagementService;
    }

    /**
     * @param extCaCrlManagementService
     *            the extCaCrlManagementService to set
     */
    public void setExtCaCrlManagementService(ExtCACRLManagementService extCaCrlManagementService) {
        this.extCaCrlManagementService = extCaCrlManagementService;
    }

    /**
     * @return the cSRManagementService
     */
    public CSRManagementService getCsrManagementService() {
        return csrManagementService;
    }

    /**
     * @return the extCaManagementService
     */
    public ExtCAManagementService getExtCaManagementService() {
        return extCaManagementService;
    }

    /**
     * @return the entityCertificateManagementCustomService
     */
    public EntityCertificateManagementCustomService getEntityCertificateManagementCustomService() {
        return entityCertificateManagementCustomService;
    }
}
