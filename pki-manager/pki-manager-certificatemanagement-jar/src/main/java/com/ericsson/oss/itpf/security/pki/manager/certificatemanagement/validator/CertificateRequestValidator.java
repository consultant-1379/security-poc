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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.*;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.inject.Inject;

import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.CertificateRequestParser;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;

/**
 * Class for validating Entity and CSR subject/subjectAltName fields.
 * 
 */
public class CertificateRequestValidator {

    // TODO Make use of sub classes here each specialized in validating the specific information, this comment will be addressed as part of TORF-59437

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    /**
     * Method for validating the CSR.
     * 
     * @param certificationRequest
     *            The pkcs10request object.
     * 
     * @throws InvalidCertificateRequestException
     *             Throws in case of given Certificate Request is invalid.
     */
    public void validate(final PKCS10CertificationRequest certificationRequest) throws InvalidCertificateRequestException {

        validateSubjectAndSAN(certificationRequest);
        validateSignature(certificationRequest);
    }

    private void validateSubjectAndSAN(final PKCS10CertificationRequest certificationRequest) throws InvalidCertificateRequestException {
        if ((certificationRequest.getSubject() != null && certificationRequest.getSubject().getRDNs().length > 0) || CertificateRequestParser.checkForSubjectAltName(certificationRequest)) {
            return;
        }
        logger.error(CSR_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY);
        throw new InvalidCertificateRequestException(CSR_SUBJECT_OR_SUBJECT_ALT_NAME_MANDATORY);
    }

    private void validateSignature(final PKCS10CertificationRequest pkcs10CertificationRequest) throws InvalidCertificateRequestException {

        try {
            final JcaPKCS10CertificationRequest jcaCertRequest = new JcaPKCS10CertificationRequest(pkcs10CertificationRequest.getEncoded()).setProvider(Constants.PROVIDER_NAME);
            ContentVerifierProvider verifierProvider;
            verifierProvider = new JcaContentVerifierProviderBuilder().build(jcaCertRequest.getPublicKey());
            final boolean isValidCSR = pkcs10CertificationRequest.isSignatureValid(verifierProvider);

            if (!isValidCSR) {
                logger.error(CSR_SIGNATURE_INVALID);
                throw new InvalidCertificateRequestException(ErrorMessages.CSR_SIGNATURE_INVALID);
            }

        } catch (final IOException e) {
            logger.error(CSR_ENCODING_FAILED);
            throw new InvalidCertificateRequestException(CSR_ENCODING_FAILED, e);
        } catch (final InvalidKeyException e) {
            logger.error(CSR_KEY_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_KEY_INVALID, e);
        } catch (final NoSuchAlgorithmException e) {
            logger.error(CSR_KEY_ALGORITHM_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_KEY_ALGORITHM_INVALID, e);
        } catch (final OperatorCreationException | PKCSException e) {
            logger.error(CSR_SIGNATURE_INVALID);
            throw new InvalidCertificateRequestException(ErrorMessages.CSR_SIGNATURE_INVALID, e);
        }
    }
}