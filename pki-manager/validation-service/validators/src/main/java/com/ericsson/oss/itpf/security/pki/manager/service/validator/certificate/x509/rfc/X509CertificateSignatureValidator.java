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

import java.security.*;
import java.security.cert.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to perform Signature validation for the given certificate
 * 
 * @author tcsramc
 *
 */
public class X509CertificateSignatureValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateSignature(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateSignature(final String caName, final X509Certificate x509Certificate) throws IssuerNotFoundException {
        logger.debug("Validating X509Certificate Signature for issuer {}", caName);
        try {
            final Signature signature = getIssuerSignature(x509Certificate);

            isValidSignature(x509Certificate, signature);

        } catch (CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, " for CA {} ", caName, certificateEncodingException.getMessage());
            throw new IssuerNotFoundException(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
        } catch (CertificateException certificateException) {
            logger.error(ErrorMessages.CERTIFICATE_NOT_FOUND, " for CA {} ", caName, certificateException.getMessage());
            throw new IssuerNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND, certificateException);
        } catch (InvalidKeyException invalidKeyException) {
            logger.error(ErrorMessages.INVALID_PUBLIC_KEY, " for CA {} ", caName, invalidKeyException.getMessage());
            throw new IssuerNotFoundException(ErrorMessages.INVALID_PUBLIC_KEY, invalidKeyException);
        } catch (CertificateNotFoundException certificateNotFoundException) {
            logger.error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND, " for CA {} ", caName, certificateNotFoundException);
            throw new IssuerNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND, certificateNotFoundException);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, " for CA {} ", caName, noSuchAlgorithmException.getMessage());
            throw new IssuerNotFoundException(ErrorMessages.ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
        } catch (SignatureException signatureException) {
            logger.error(ErrorMessages.INVALID_SIGNATURE, " for CA {} ", caName, signatureException.getMessage());
            throw new IssuerNotFoundException(ErrorMessages.INVALID_SIGNATURE, signatureException);
        }
    }

    private Signature getIssuerSignature(final X509Certificate x509Certificate) throws CertificateException, CertificateNotFoundException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, CertificateEncodingException {
        final X509Certificate cACertificate = getIssuerCertificate(x509Certificate);

        final Signature signature = getSignature(x509Certificate, cACertificate);
        return signature;
    }

    private X509Certificate getIssuerCertificate(final X509Certificate x509Certificate) throws CertificateNotFoundException {
        final X509Certificate issuerCertificate = extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate);
        return issuerCertificate;
    }

    private Signature getSignature(final X509Certificate x509Certificate, final X509Certificate cACertificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            CertificateEncodingException {
        final Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initVerify(cACertificate.getPublicKey());
        signature.update(x509Certificate.getTBSCertificate());
        return signature;
    }

    private void isValidSignature(final X509Certificate x509Certificate, final Signature signature) throws IssuerNotFoundException {
        try {
            signature.verify(x509Certificate.getSignature());
        } catch (SignatureException signatureException) {
            logger.error(ErrorMessages.INVALID_SIGNATURE, "for given CA {} ", x509Certificate.getIssuerDN());
            throw new IssuerNotFoundException(ErrorMessages.INVALID_SIGNATURE + "for given Certificate", signatureException);

        }
    }

}
