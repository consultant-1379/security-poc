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

package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.SignatureAlgorithmValidator;

/**
 * This class validates SignatureAlgorithm in certificate profile for a {@link CertificateProfile}
 */
public class CertificateProfileSignatureAlgorithmValidator implements CommonValidator<CertificateProfile> {

    @Inject
    Logger logger;

    @Inject
    SignatureAlgorithmValidator signatureAlgorithmValidator;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificate) throws ValidationException {
        validateSignatureAlgorithm(certificate.getSignatureAlgorithm());
    }

    private void validateSignatureAlgorithm(final Algorithm signatureAlgorithm) throws AlgorithmException, AlgorithmNotFoundException {
        logger.debug("Validating Signature Algorithm in Certificate Profile {} ", signatureAlgorithm);

        signatureAlgorithmValidator.validate(signatureAlgorithm);

    }

}
