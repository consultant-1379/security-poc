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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc;

import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.helper.AlgorithmLoader;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to check whether algorithm in the imported certificate is present in the database or not.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateSignatureAlgorithmValidator implements CommonValidator<CACertificateValidationInfo> {
    @Inject
    Logger logger;

    @Inject
    AlgorithmLoader algorithmLoader;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateSignatureAlgorithm(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());

    }

    private void validateSignatureAlgorithm(final String caName, final X509Certificate x509Certificate) throws AlgorithmNotFoundException {
        logger.debug("Validating X509Certificate SignatureAlgorithm for CA and Algorithm is {} ", caName, x509Certificate.getSigAlgName());
        final List<Algorithm> algorithms = algorithmLoader.getSupportedAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM);
        if (algorithms.size() == 0) {
            logger.error(ErrorMessages.ALGORITHM_NOT_FOUND_IN_DB, " for AlgorithmType {} and Caname is {} ", AlgorithmType.SIGNATURE_ALGORITHM, caName);
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND_IN_DB);
        }
        final Iterator<Algorithm> iterator = algorithms.iterator();
        final List<String> algorithm = new ArrayList<String>();

        while (iterator.hasNext()) {
            algorithm.add(iterator.next().getOid());
        }

        if (!algorithm.contains(x509Certificate.getSigAlgOID())) {
            logger.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, " for CA {} ", caName, " Algorithm present in the certificate is {} ", x509Certificate.getSigAlgName());
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_IS_NOT_FOUND);
        }

    }
}
