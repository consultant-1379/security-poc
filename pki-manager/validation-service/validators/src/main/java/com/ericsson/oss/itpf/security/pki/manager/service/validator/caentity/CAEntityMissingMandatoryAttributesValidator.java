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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;


/**
 * This class is used to check whether mandatory parameters are present for a {@link CaEntity}
 *
 * @author xtelsow
 */
public class CAEntityMissingMandatoryAttributesValidator implements CommonValidator<CAEntity> {
    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity) throws ValidationException {
        validateMandatoryAttributes(caEntity);
    }

    /**
     * This Method validates the mandatory params of caentity i.e {@link CAEntity}
     *
     * @param caEntity
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     */
    private void validateMandatoryAttributes(final CAEntity caEntity) throws MissingMandatoryFieldException {
        logger.debug("Validating Mandatory params for CA Entity {}", caEntity.getCertificateAuthority().getName());

        if (caEntity.getCertificateAuthority() == null) {
            logger.error("Certificate Authority cannot be null");
            throw new MissingMandatoryFieldException("Certificate AUthority cannot be null");
        }

        if (caEntity.getCertificateAuthority().getName() == null) {
            logger.error("Name cannot be null");
            throw new MissingMandatoryFieldException("Name cannot be null");
        }

        if (caEntity.getCertificateAuthority().getSubject() == null) {
            logger.error("Subject cannot be null");
            throw new MissingMandatoryFieldException("Subject cannot be null");
        }

        if (caEntity.getCertificateAuthority().getName().trim().isEmpty()) {
            logger.error("Name cannot be empty");
            throw new MissingMandatoryFieldException("Name cannot be empty");
        }

        logger.debug("Completed Validating Mandatory params for CA Entity {}", caEntity.getCertificateAuthority().getName());
    }
}