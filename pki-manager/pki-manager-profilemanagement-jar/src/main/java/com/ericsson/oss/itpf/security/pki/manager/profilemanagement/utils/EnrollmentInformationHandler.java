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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.utils;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.enrollment.EnrollmentURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 *
 * This is the handler class to fetch the EnrollmentInfo Details,form the EnrollmentObject and return it to CREDM. The EnrollmentInfo object consists of Enrollment URL, CA Certificate and Trust
 * Distribution URL of the given entity.
 *
 * @author xbensar
 */
public class EnrollmentInformationHandler {

    @Inject
    private PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Inject
    private CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    private Logger logger;

    private final static String URL_SEPARATOR = "/";
    private final static String DUMMYTRUSTDISTRIBUTIONURL = "localhost:8080/rootCA_127/profile/12 A9 4H";
    private final static String CONTEXT_NAME_SCEP = "pkira-scep";
    private final static String CONTEXT_NAME_CMP = "pkira-cmp";
    private final static String HTTP_PROTOCOL = "http://";

    /**
     * This method is used to form the EnrollmentInfo object and return it. The EnrollmentInfo object consists of Enrollment URL, CA Certificate and Trust Distribution URL of the given entity.
     *
     * @param entity
     *            Complete entity object fetched using the entityName
     * @param enrollmentType
     *            Type of Enrollment.Can be SCEP or CMPV2
     * @return EnrollmentInfo is the EnrollmentInfo object consisting of fields like CACertificate in X509 Format, EnrollmentURL(a concatenated string LoadBalancerAddress and EnrollmentType) and
     *         TrustDistributionURL
     * @throws EntityServiceException
     *             thrown when there are any DB Errors retrieving the Entity Data.
     * @throws EnrollmentURLNotFoundException
     *             thrown when LoadBalancerAddress is not retrieved from the model
     * @throws InvalidEntityException
     *             thrown when Issuer of the given entity does not have ACTIVE certificates.
     *
     */
    public EnrollmentInfo getEnrollmentInformation(final Entity entity, final EnrollmentType enrollmentType) throws EntityServiceException, EnrollmentURLNotFoundException, InvalidEntityException {

        logger.info("Entering method getEnrollmentInformation of class EnrollmentInformationHandler");

        final EnrollmentInfo enrollmentInfo = new EnrollmentInfo();

        final String issuerName = entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName();

        X509Certificate caCertificate = null;

        try {
            caCertificate = caCertificatePersistenceHelper.getActiveCertificate(issuerName);

            if (caCertificate == null) {
                logger.error("CA with name {} not found or does not have ACTIVE certificate", issuerName);
                throw new InvalidEntityException("CA with name " + issuerName + " not found or does not have ACTIVE certificate");
            }

            enrollmentInfo.setCaCertificate(caCertificate);

        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new EntityServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        } catch (CertificateException | IOException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_GETTING_ISSUER_CERTIFICATE, exception.getMessage());
            throw new EntityServiceException(ErrorMessages.ERROR_OCCURED_IN_GETTING_ISSUER_CERTIFICATE, exception);
        }

        final String sbLoadBalancerIPv4Address = pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address();
        final String sbLoadBalancerIPv6Address = pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address();

        if (sbLoadBalancerIPv4Address == null && sbLoadBalancerIPv6Address == null) {
            throw new EnrollmentURLNotFoundException("Enrollment URL" + ProfileServiceErrorCodes.NOT_FOUND);
        }

        if (sbLoadBalancerIPv4Address != null) {
            final String ipv4EnrollmentAddress = getEnrollmentAddress(enrollmentType, sbLoadBalancerIPv4Address, issuerName);
            enrollmentInfo.setEnrollmentURL(ipv4EnrollmentAddress);
            enrollmentInfo.setIpv4EnrollmentURL(ipv4EnrollmentAddress);
        }

        if (sbLoadBalancerIPv6Address != null) {
            final String ipv6EnrollmentAddress = getEnrollmentAddress(enrollmentType, sbLoadBalancerIPv6Address, issuerName);
            enrollmentInfo.setIpv6EnrollmentURL(ipv6EnrollmentAddress);
        }

        // Since TDPS is not ready, a dummy trustDistributionURL is set to EnrollmentInfo object.
        enrollmentInfo.setTrustDistributionPointURL(DUMMYTRUSTDISTRIBUTIONURL);

        logger.info("End of method getEnrollmentInformation of class EnrollmentInformationHandler ");

        return enrollmentInfo;
    }

    private String getEnrollmentAddress(final EnrollmentType enrollmentType, final String hostAddress, final String issuerName) throws EnrollmentURLNotFoundException {
        String enrollmentAddress = null;

        switch (enrollmentType) {
        case scep:
            enrollmentAddress = HTTP_PROTOCOL + hostAddress + Constants.COLON_OPERATOR + Constants.SCEP_PORT + URL_SEPARATOR + CONTEXT_NAME_SCEP + URL_SEPARATOR + issuerName;
            break;

        case cmp:
            enrollmentAddress = HTTP_PROTOCOL + hostAddress + Constants.COLON_OPERATOR + Constants.CMP_PORT + URL_SEPARATOR + CONTEXT_NAME_CMP + URL_SEPARATOR + issuerName;
            break;

        default:
            logger.error("Invalid Enrollment Type {}", enrollmentType);
            throw new EnrollmentURLNotFoundException("Unsupported Enrollment Type");
        }

        return enrollmentAddress;
    }
}
