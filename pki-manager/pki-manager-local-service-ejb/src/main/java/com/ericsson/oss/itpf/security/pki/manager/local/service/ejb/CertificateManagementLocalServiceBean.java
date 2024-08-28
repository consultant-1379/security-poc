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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.security.cert.X509Certificate;
import java.util.*;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.EntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation.InstrumentationAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class provides interfaces to fetch Certificate,CertificateChain,TrustCertificates and list of entity certificates.
 *
 * @author tcsramc
 *
 */
@Stateless
public class CertificateManagementLocalServiceBean implements CertificateManagementLocalService {

    @Inject
    EntityCertificateManager entityCertificateManager;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    /**
     * This method is used to get Certificate Chain for the given Entity
     */
    @Override
    public CertificateChain getCertificateChain(final String entityName) throws CertificateServiceException, InvalidCAException, InvalidCertificateStatusException, InvalidEntityException,
            InvalidEntityAttributeException {
        final CertificateChain certificateChain = entityCertificateManager.getCertificateChain(entityName, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE).get(0);
        return certificateChain;
    }

    /**
     * This method is used to get Trust Certificates for the given Entity.
     */
    @Override
    public List<Certificate> getTrustCertificates(final String entityName) {
        final List<Certificate> trustCertificates = entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE);
        final List<Certificate> uniqueTrustCertificates = entityCertificateManager.removeDuplicatesCertificates(new ArrayList<Certificate>(trustCertificates));
        return uniqueTrustCertificates;
    }

    /**
     * This method is used to generate new Certificate for the given Entity.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYCERTIFICATEMGMT, metricType = MetricType.GENERATE)
    public Certificate generateCertificate(final String entityName, final CertificateRequest certificateRequest) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {
        final Certificate certificate = entityCertificateManager.generateCertificate(entityName, certificateRequest, RequestType.NEW);
        return certificate;

    }

    /**
     * This method is used to get Certificate for the given entity based on given status.
     */
    @Override
    public List<Certificate> getEntityCertificates(final String entityName) throws CertificateNotFoundException, CertificateServiceException, EntityNotFoundException, InvalidEntityAttributeException {
        final List<Certificate> certificates = entityCertificateManager.listCertificates(entityName, CertificateStatus.ACTIVE);
        return certificates;
    }

    /**
     * This method is used to validate the certificate Chain of the X509Certificate
     */
    @Override
    public void validateCertificateChain(final X509Certificate certificate) throws CertificateServiceException, CertificateNotFoundException, ExpiredCertificateException, RevokedCertificateException {
        final Certificate certificateToValidate = certificatePersistenceHelper.getCertificate(certificate);
        certificatePersistenceHelper.validateCertificateChain(certificateToValidate, EnumSet.of(CertificateStatus.REVOKED));
    }

}
