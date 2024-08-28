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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import java.util.List;
import java.util.Map;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CRLManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.CRLManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation.InstrumentationAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.CRLGenerationStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.cdps.CRLPublishUnpublishStatus;

/**
 * This class implements {@link CRLManagementService}
 *
 * @author xbensar
 *
 */
@Stateless
@EServiceQualifier("1.0.0")
@ErrorLogAnnotation()
public class CRLManagementServiceBean implements CRLManagementService {

    @Inject
    CRLManager crlManager;

    @Inject
    CRLManagementAuthorizationManager cRLManagementAuthorizationManager;

    @Inject
    Logger logger;

    /**
     * TODO:This will be handled in the TORF-44799
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.CRLMGMT, metricType = MetricType.GENERATE)
    @Authorize(resource = "caEntity_cert_mgmt", action = "update", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void generateCRL(final CACertificateIdentifier caCertIdentifier) throws CANotFoundException, CertificateNotFoundException, CRLGenerationException, CRLServiceException,
            ExpiredCertificateException, InvalidCRLGenerationInfoException, RevokedCertificateException {
        crlManager.generateCRL(caCertIdentifier);
    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.CRLMGMT, metricType = MetricType.GENERATE)
    @Authorize(resource = "caEntity_cert_mgmt", action = "update", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public Map<CACertificateIdentifier, CRLGenerationStatus> generateCRL(final List<String> caEntityNameList, final CertificateStatus... certificateStatus) throws InvalidCertificateStatusException {
        logger.debug("Generating CRLs for a list of CA Names");
        return crlManager.generateCRL(caEntityNameList, certificateStatus);
    }

    @Override
    @Authorize(resource = "read_crls", action = "read", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public List<CRLInfo> getAllCRLs(final CACertificateIdentifier caCertIdentifier) throws CAEntityNotInternalException, CANotFoundException, CertificateNotFoundException, CRLGenerationException,
            CRLNotFoundException, CRLServiceException, InvalidCAException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException {
        logger.debug("Inside getAllCRLs method in CRLManagementServiceBean Class for the caname{}", caCertIdentifier.getCaName());
        final List<CRLInfo> crlList = crlManager.getAllCRLs(caCertIdentifier);
        return crlList;
    }

    @Override
    @Authorize(resource = "read_crls", action = "read", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public Map<CACertificateIdentifier, List<CRLInfo>> getAllCRLs(final String caEntityName, final CertificateStatus certificateStatus) throws CAEntityNotInternalException, CANotFoundException,
            CertificateNotFoundException, CRLServiceException, InvalidCAException, InvalidEntityAttributeException {
        logger.debug("Fetching all CRLs for the CA{} with certificate having certificateStatus{}", caEntityName, certificateStatus);
        return crlManager.getAllCRLs(caEntityName, certificateStatus);
    }

    @Override
    @Authorize(resource = "read_crls", action = "read", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public CRLInfo getCRLByCACertificate(final CACertificateIdentifier caCertificateIdentifier) throws CAEntityNotInternalException, CANotFoundException, CertificateNotFoundException,
            CRLNotFoundException, CRLServiceException, ExpiredCertificateException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException, RevokedCertificateException {
        logger.debug("Fetching CRL by CACertificate{}", caCertificateIdentifier.getCaName());
        return crlManager.getCRLByCACertificate(caCertificateIdentifier);

    }

    @Override
    public Map<CACertificateIdentifier, List<CRLInfo>> getCRL(final String caEntityName, final CertificateStatus certificateStatus, final boolean isChainRequired) throws CANotFoundException,
            CAEntityNotInternalException, CertificateNotFoundException, CRLServiceException, InvalidCertificateStatusException, InvalidEntityAttributeException {
        cRLManagementAuthorizationManager.authorizeGetCRL();
        logger.debug("Fetching CRL by CAName and Certificate Staus{}", caEntityName);
        return crlManager.getCRLbyCAName(caEntityName, certificateStatus, isChainRequired);
    }

    @Override
    @Authorize(resource = "read_crls", action = "read", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public CRLInfo getCRL(final String caEntityName, final CRLNumber crlNumber) throws CAEntityNotInternalException, CANotFoundException, CRLNotFoundException, CRLServiceException,
            InvalidCAException, InvalidEntityAttributeException {
        logger.debug("get CRL By CAName {} and CRLNumber {}", caEntityName, crlNumber);
        return crlManager.getCRLByCRLNumber(caEntityName, crlNumber);
    }

    @Override
    @Authorize(resource = "caEntity_cert_mgmt", action = "update", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public Map<String, CRLPublishUnpublishStatus> publishCRLToCDPS(final List<String> caNames) throws CRLServiceException, CANotFoundException {
        logger.debug("publishCRLTOCDPS method in CRLManagementServiceBean class");
        return crlManager.publishCRLToCDPS(caNames);
    }

    @Override
    @Authorize(resource = "caEntity_cert_mgmt", action = "update", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public Map<String, CRLPublishUnpublishStatus> unpublishCRLFromCDPS(final List<String> caNames) throws CRLServiceException, CANotFoundException {
        logger.debug("unpublishCRLFromCDPS method in CRLManagementServiceBean class");
        return crlManager.unpublishCRLFromCDPS(caNames);
    }

}
