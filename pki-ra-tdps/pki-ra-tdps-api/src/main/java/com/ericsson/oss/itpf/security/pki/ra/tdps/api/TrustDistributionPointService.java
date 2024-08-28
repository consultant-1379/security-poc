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
package com.ericsson.oss.itpf.security.pki.ra.tdps.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionResourceNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;

/**
 * This class is a Local Stateless EJB which provides CA/Entity certificate based on the entityName.
 * 
 * @author tcsdemi
 *
 */
@EService
@Local
public interface TrustDistributionPointService {

    /**
     * This Service is used to retrieve certificate from Trust Distribution database based on entityType/Name and certificateSerialNumber. TrustDistributionPointService is invoked from
     * TDPSRestResource invokes this EJB service.
     * 
     * @see com.ericsson.oss.itpf.security.tdps.rest.resources.TDPSRestResource
     * 
     * @param trustDistributionParameters
     *            These are the input parameters which are extracted from the Rest URL. These are entityType,entityName, IssuerName, CertificateStatus, certificateSerialNumber
     * 
     * @return returns the certificate byte array which can be written into a .crt file
     * 
     * @throws TrustDistributionResourceNotFoundException
     *             Thrown in case a certificate is not found in Database with the given input parameters.
     * 
     * @throws TrustDistributionServiceException
     *             Thrown in case there is any internal exception at application level for eg: any db related error which is then wrapped to service exception.
     */
    byte[] getCertificate(final TrustDistributionParameters trustDistributionParameters) throws TrustDistributionResourceNotFoundException, TrustDistributionServiceException;

}