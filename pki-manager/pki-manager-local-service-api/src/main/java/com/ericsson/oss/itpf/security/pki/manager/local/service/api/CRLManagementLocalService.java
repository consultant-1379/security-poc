/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.local.service.api;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * This is an interface for CRLManagement. It provides a method which is used to create a new transaction if a request is not associated with any transaction.
 * 
 * @author xramdag
 * 
 */
@EService
@Local
public interface CRLManagementLocalService {

    /**
     * This method updates the CRL publish/unpublish status in DB using CACertificateIdentifier and publishedToCDPS
     * 
     * @param caCertificateIdentifiers
     *            it holds the list of CACertificateIdentifier it contains CAName and Certificate Serial Number
     * 
     * @param isPublishedToCDPS
     *            it is a boolean value either true or false
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given certificate serial number.
     * @throws CRLNotFoundException
     *             thrown when CRL for the requested CA does not exist.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws ExpiredCertificateException
     *             thrown when the fetch CRL request is raised for an expired certificate.
     * @throws RevokedCertificateException
     *             thrown when the fetch CRL request is raised for a revoked certificate.
     */
    void updateCRLPublishUnpublishStatus(final List<CACertificateIdentifier> caCertificateIdentifiers, final boolean isPublishedToCDPS) throws CANotFoundException, CertificateNotFoundException, CRLNotFoundException,
            CRLServiceException, ExpiredCertificateException, RevokedCertificateException;

    /**
     * This method will hard delete corresponding invalid crls for the caCertificateIdentifiers
     * 
     * @param caCertificateIdentifiers
     *            is the CACertificateIdentifier which is used to identify the CA certificate for which the CRL need to be deleted.
     */
    void deleteInvalidCRLs(final List<CACertificateIdentifier> caCertificateIdentifiers);

    /**
     * This method get the CRL information from DB using CACertificateIdentifier
     * 
     * @param caCertificateIdentifier
     *            it holds the CAName and Certificate Serial Number
     * 
     * @return CRL object which contains the attributes like X509CRL, thisUpdate, nextUpdate,CRLNumber,CRLStatus.
     * 
     * @throws CANotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given certificate serial number.
     * @throws CRLNotFoundException
     *             thrown when CRL for the requested CA does not exist.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws ExpiredCertificateException
     *             thrown when the fetch CRL request is raised for an expired certificate.
     * @throws RevokedCertificateException
     *             thrown when the fetch CRL request is raised for a revoked certificate.
     */
    CRLInfo getCRLByCACertificateIdentifier(final CACertificateIdentifier caCertificateIdentifier) throws CANotFoundException, CertificateNotFoundException, CRLNotFoundException, CRLServiceException,
            ExpiredCertificateException, RevokedCertificateException;

    /**
     * This method will publish all eligible latest CRLs on Start up
     * 
     * @return - CACertificateIdentifier list
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     */
    List<CACertificateIdentifier> getAllPublishCRLs() throws CRLServiceException;

    /**
     * This method will unpublish all CRLs on Start up
     * 
     * @return - CACertificateIdentifier list
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     */
    List<CACertificateIdentifier> getAllUnPublishCRLs() throws CRLServiceException;
}
