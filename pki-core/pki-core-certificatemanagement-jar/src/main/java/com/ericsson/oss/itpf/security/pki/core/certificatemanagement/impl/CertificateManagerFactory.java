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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.qualifier.CertificateManagerType;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.qualifier.EntityTypeEnum;

/**
 * Factory class which provides the respective Certificate Managers for CAEntity and Entity basing on the {@link CertificateGenerationInfo}
 * 
 */
public class CertificateManagerFactory {
    @Inject
    @CertificateManagerType(EntityTypeEnum.CA_ENTITY)
    CertificateManager caEntityCertificateManager;

    @Inject
    @CertificateManagerType(EntityTypeEnum.ENTITY)
    CertificateManager entityCertificateManager;

    @Inject
    Logger logger;
    /**
     * Provides corresponding CertificateManager instance
     *
     * @param certificateGenerationInfo
     *            Certificate generation info basing on which the corresponding manager is identified
     * @return corresponding {@link CertificateManager} object
     */
    public CertificateManager getManager(final CertificateGenerationInfo certificateGenerationInfo) {
        if (isCAEntity(certificateGenerationInfo)) {
            logger.info("Given Entity {} is a CA Entity", certificateGenerationInfo.getCAEntityInfo().getName());
            return caEntityCertificateManager;
        } else {
            logger.info("Given Entity {} is not a CA Entity", certificateGenerationInfo.getEntityInfo().getName());
            return entityCertificateManager;
        }
    }

    private boolean isCAEntity(final CertificateGenerationInfo certificateGenerationInfo) {
        final List<CertificateExtension> certificateExtensions = certificateGenerationInfo.getCertificateExtensions().getCertificateExtensions();

        for (final CertificateExtension certificateExtension : certificateExtensions) {
            if (certificateExtension instanceof BasicConstraints) {
                final BasicConstraints basicConstraints = (BasicConstraints) certificateExtension;
                if (basicConstraints.isCA()) {
                    return true;
                }
            }
        }
        return false;
    }
}
