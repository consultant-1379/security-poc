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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

/**
 * Interface for common Certificate Management operations for CAEntity and Entity. Provides below operation
 * <ul>
 * <li>List certificates based on Certificate status</li>
 * </ul>
 * 
 */
@EService
@Local
public interface CertificateManagementServiceLocal {

    /**
     * The filter data to be applied in order to fetch the certificates matching with the filter.
     * 
     * @param certificateFilter
     *            The filter data to be applied to get certificates.
     * @return list of certificates for the given filter data.
     * @throws CertificateException
     * 
     *             Thrown in case of any exceptions while filtering the certificates .
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    List<Certificate> getCertificates(final CertificateFilter certificateFilter) throws CertificateException, CertificateServiceException;

    /**
     * Count the exact rows number matching with the filter.
     * 
     * @param certificateFilter
     *            The filter data to be applied to get certificates.
     * @return count number of rows matching with the filter.
     * @throws CertificateException
     *             Thrown in case of any exceptions while retrieving the certificates count.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    long getCertificateCount(final CertificateFilter certificateFilter) throws CertificateException, CertificateServiceException;

}
