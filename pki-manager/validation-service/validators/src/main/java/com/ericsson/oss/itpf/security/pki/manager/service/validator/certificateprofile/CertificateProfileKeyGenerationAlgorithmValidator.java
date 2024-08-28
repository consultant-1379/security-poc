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

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.KeyGenerationAlgorithmsValidator;

/**
 * This class validates Certificate Profile Key Generation Algorithm for a {@link CertificateProfile}
 */
public class CertificateProfileKeyGenerationAlgorithmValidator implements CommonValidator<CertificateProfile> {

    @Inject
    Logger logger;

    @Inject
    KeyGenerationAlgorithmsValidator keyGenerationAlgorithmValidators;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateKeyGenerationAlgorithms(certificateProfile.getKeyGenerationAlgorithms());

    }

    private void validateKeyGenerationAlgorithms(final List<Algorithm> keyGenerationAlgorithms) throws AlgorithmException, AlgorithmNotFoundException {
        logger.debug("Validating KeyGenerationAlgorithmList in Certificate Profile {} ", keyGenerationAlgorithms);

        keyGenerationAlgorithmValidators.validate(keyGenerationAlgorithms);
    }
}