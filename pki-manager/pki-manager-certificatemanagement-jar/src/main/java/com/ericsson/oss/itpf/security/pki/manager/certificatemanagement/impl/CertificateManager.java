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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.EnumSet;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateFilterValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.EntityTypeFilter;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.FilterResponseType;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * Class used for list/count Certificates by Certificate filter
 * 
 */
public class CertificateManager {

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    CertificateFilterValidator certificateFilterValidator;

    @Inject
    Logger logger;

    /**
     * Validate CertificateFilter object and fetch the list of certificates matching with certificate filter.
     * 
     * @param certificateFilter
     *            The filter data to be applied to get certificates.
     * @return list of certificates for the given filter data.
     * @throws CertificateException
     *             Thrown in case of any exceptions while filtering the certificates .
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    public List<Certificate> getCertificates(final CertificateFilter certificateFilter) throws CertificateException, CertificateServiceException {

        try {
            logger.debug("Fetch Certificates and validate CertificateFilter {} ", certificateFilter);

            certificateFilterValidator.validateCertificateFilter(certificateFilter);

            final EnumSet<EntityType> entityTypeFilter = EntityTypeFilter.getEntityType(certificateFilter.getEntityTypes());

            final List<CertificateData> certificateDataList = (List<CertificateData>) certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.LIST);

            logger.debug("Fetched Certificates by CertificateFilter");

            return certificateModelMapper.toObjectModel(certificateDataList, false);
        } catch (PersistenceException persistenceException) {
            logger.error(INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(INTERNAL_ERROR + persistenceException);
        } catch (java.security.cert.CertificateException certificateException) {
            logger.error(UNEXPECTED_ERROR, certificateException.getMessage());
            throw new CertificateServiceException(UNEXPECTED_ERROR + certificateException);
        } catch (IOException ioException) {
            logger.error(UNEXPECTED_ERROR, ioException.getMessage());
            throw new CertificateServiceException(UNEXPECTED_ERROR + ioException);
        }
    }

    /**
     * Validate CertificateFilter Object and Fetch certificates count matching with the filter.
     * 
     * @param certificateFilter
     *            The filter data to be applied to get certificates.
     * @return count number of rows matching with the filter.
     * @throws CertificateException
     *             Thrown in case of any exceptions while retrieving the certificates count.
     * @throws CertificateException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    public Long getCertificateCount(final CertificateFilter certificateFilter) throws CertificateException, CertificateServiceException {

        try {
            logger.debug("Count Certificates and validate CertificateFilter {} ", certificateFilter);

            final EnumSet<EntityType> entityTypeFilter = EntityTypeFilter.getEntityType(certificateFilter.getEntityTypes());

            final Long certificatesCount = ((BigInteger) certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.COUNT)).longValue();

            logger.debug("Counted Certificates by CertificateFilter {} ", certificateFilter);

            return certificatesCount;
        } catch (PersistenceException persistenceException) {
            logger.error(INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(INTERNAL_ERROR + persistenceException);
        } catch (CertificateException certificateException) {
            logger.error(UNEXPECTED_ERROR, certificateException.getMessage());
            throw new CertificateServiceException(UNEXPECTED_ERROR + certificateException);
        }
    }
}
