/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb.utility;

import java.security.cert.CertificateExpiredException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

/**
 * This is a CertificateManagementUtility class which contains the helper methods.
 *
 * @author xkihari
 *
 */
public class CertificateManagementUtility {

    @Inject
    Logger logger;

    /**
     * Method is used to remove the expired certificates.
     *
     * @param listOfCertificates
     *            Certificate list fetched from database based on the certificate status
     *
     * @return List of Certificate objects.
     */
    public List<Certificate> removeExpiredCertificates(List<Certificate> listOfCertificates) {
        List<Certificate> certsTobeRemoved = new ArrayList<>();
        for (Certificate certificate : listOfCertificates) {
            try {
                certificate.getX509Certificate().checkValidity();
            } catch (final CertificateExpiredException exception) {
                final String errorMessage = "The certificate is expired. Removing the expired certificate";
                logger.warn(errorMessage, exception.getMessage());
                certsTobeRemoved.add(certificate);
            } catch (final Exception exception) {
                logger.error("The certificate is invalid [{}]", exception.getMessage());
            }
        }
        listOfCertificates.removeAll(certsTobeRemoved);
        return listOfCertificates;
    }
}
