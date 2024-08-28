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
package com.ericsson.oss.itpf.security.pki.manager.validation.service;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.CommonValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/**
 * Used to provide the respective validation services.
 */
public class ValidationServiceManager {

    @Inject
    @ServiceQualifier(ItemType.TRUST_PROFILE)
    CommonValidationService trustProfileValidationService;

    @Inject
    @ServiceQualifier(ItemType.ENTITY_PROFILE)
    CommonValidationService entityProfileValidationService;

    @Inject
    @ServiceQualifier(ItemType.CERTIFICATE_PROFILE)
    CommonValidationService certificateProfileValidationService;

    @Inject
    @ServiceQualifier(ItemType.CA_ENTITY)
    CommonValidationService caEntityValidationService;

    @Inject
    @ServiceQualifier(ItemType.ENTITY)
    CommonValidationService entityValidationService;

    @Inject
    @ServiceQualifier(ItemType.X509CERTIFICATE)
    CommonValidationService x509CertificateValidationService;

    @Inject
    @ServiceQualifier(ItemType.GENERATE_CSR)
    CommonValidationService exportCSRValidationService;

    @Inject
    @ServiceQualifier(ItemType.ENTITY_OTP)
    CommonValidationService otpValidationService;

    /**
     * @return CommonValidationService Returns EntityProfileValidationService instance.
     */
    public CommonValidationService getEntityProfileValidationService() {
        return entityProfileValidationService;
    }

    /**
     * @return CommonValidationService Returns TrustProfileValidationService instance.
     */
    public CommonValidationService getTrustProfileValidationService() {
        return trustProfileValidationService;
    }

    /**
     * @return CommonValidationService Returns CertificateProfileValidationService instance.
     */
    public CommonValidationService getCertificateProfileValidationService() {
        return certificateProfileValidationService;
    }

    /**
     * @return CommonValidationService Returns caEntityValidationService instance.
     */
    public CommonValidationService getCaEntityValidationService() {
        return caEntityValidationService;
    }

    /**
     * @return CommonValidationService Returns entityValidationService instance.
     */
    public CommonValidationService getEntityValidationService() {
        return entityValidationService;
    }

    /**
     * 
     * @return CommonValidationService Returns CertificateValidationService instance.
     */
    public CommonValidationService getX509CertificateValidationService() {
        return x509CertificateValidationService;
    }

    /**
     * @return the exportCSRValidationService
     */
    public CommonValidationService getExportCSRValidationService() {
        return exportCSRValidationService;
    }

    /**
     * @return the otpValidationService
     */
    public CommonValidationService getOtpValidationService() {
        return otpValidationService;
    }

}