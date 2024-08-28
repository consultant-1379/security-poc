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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.privateinternet;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidator;

/**
 * This abstract class contains all common methods that are used by all private certificate extension validators. This class is extended by AuthorityInformationAccessValidator.
 * 
 */
public abstract class PrivateInternetExtensionValidator implements CertificateExtensionValidator {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    /**
     * This method checks whether the certificate extension is defined for the profile or not
     * 
     * @param certificateExtension
     *            certificate extension object
     * @return boolean true if defined or false if not defined
     */
    public boolean isCertificateExtensionDefined(final CertificateExtension certificateExtension) {
        if (certificateExtension == null) {
            return false;
        }
        return true;
    }

    /**
     * This method returns if the given certificate extension is marked as critical or not
     * 
     * @param certificateExtension
     *            certificate extension object
     * @return boolean true if marked as critical or false if not marked as critical
     */
    public boolean isCertificateExtensionCritical(final CertificateExtension certificateExtension) {
        if (certificateExtension.isCritical()) {
            return true;
        }
        return false;
    }
}
