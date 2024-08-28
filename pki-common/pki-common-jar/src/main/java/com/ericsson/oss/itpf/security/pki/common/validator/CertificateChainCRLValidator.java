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
package com.ericsson.oss.itpf.security.pki.common.validator;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreFileReader;
import com.ericsson.oss.itpf.security.pki.common.util.PKIXCertificatePathBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.UnsupportedCRLVersionException;

/**
 * All CRL validations are done in this class.
 * 
 * @author tcsramc
 * 
 */
public class CertificateChainCRLValidator {

    @Inject
    PKIXCertificatePathBuilder pKIXCertificatePathBuilder;

    @Inject
    KeyStoreFileReader keyStoreFileReader;

    @Inject
    Logger logger;

    /**
     * This method is used to validate CRL for a certificate Validation includes CRLIssuerNull,CRLVersionCheck,CRLValiditycheck and DigitalSignaturValidation
     * 
     * @param certificate
     *            certificate to verify
     * @param vendorCertificates
     *            vendor certificates set.
     * @param caCertificates
     *            caCertificates
     * @throws CRLValidationException
     *             is thrown when any parsing error occurs while generating CRLs
     * @throws KeyStoreException
     *             is thrown if any error occurs while reading/fetching from keystore.
     */
    public void validateIssuerCRL(final X509Certificate certificate, final X509CRL issuerCRL, final String issuerName, final Set<X509Certificate> vendorCertificates,
            final Set<X509Certificate> caCertificates) throws CRLValidationException, KeyStoreException {
        try {
            logger.info("validate CRL for a certificate Validation includes CRLIssuerNull,CRLVersionCheck,CRLValiditycheck and DigitalSignaturValidation");
            if (issuerCRL != null) {
                final PublicKey publicKey = getPublicKeyFromTrusts(issuerName, vendorCertificates, caCertificates);
                isCRLIssuerNull(issuerCRL);

                verifyCRLDigitalSignature(issuerCRL, publicKey);
                verifyCRLVersion(issuerCRL);
                checkCRLvalidatity(issuerCRL);

            }
        } catch (IOException ioException) {
            throwCRLValidationException(ErrorMessages.IO_EXCEPTION, ioException);

        } catch (CRLException crlException) {
            throwCRLValidationException(ErrorMessages.CRL_FORMAT_ERROR, crlException);

        } catch (InvalidKeyException invalidKeyException) {
            throwCRLValidationException(ErrorMessages.INVALID_PUBLIC_KEY, invalidKeyException);

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throwCRLValidationException(ErrorMessages.INVALID_ALGORITHM, noSuchAlgorithmException);

        } catch (NoSuchProviderException noSuchProviderException) {
            throwCRLValidationException(ErrorMessages.NO_SUCH_PROVIDER, noSuchProviderException);

        } catch (SignatureException signatureException) {
            throwCRLValidationException(ErrorMessages.DIGITAL_SIGNATURE_ERROR, signatureException);

        } catch (UnsupportedCRLVersionException unsupportedCRLVersionException) {
            throwCRLValidationException(ErrorMessages.CRL_VERSION_ERROR, unsupportedCRLVersionException);
        }
    }

    /**
     * This method is used to validate CRL doing basic validation checks and verifying the digital signature of the CRL.
     * 
     * @param name
     *            The subject CN of the certificate
     * @param crlToVerify
     *            The CRL to be validated.
     * @param trustedCertificates
     *            The trusted certificates to be used to fetch the public key to verify CRL.
     * @throws CRLValidationException
     *             is thrown when any parsing error occurs while generating CRLs
     * @throws KeyStoreException
     *             is thrown if any error occurs while reading/fetching from keystore.
     */
    public void validateIssuerCRL(final String name, final X509CRL crlToVerify, final Set<X509Certificate> trustedCertificates) throws CRLValidationException, KeyStoreException {
        try {
            logger.info("validate CRL doing basic validation checks and verifying the digital signature of the CRL.");
            if (crlToVerify != null) {
                final PublicKey publicKey = getPublicKey(name, trustedCertificates);

                isCRLIssuerNull(crlToVerify);
                verifyCRLDigitalSignature(crlToVerify, publicKey);

                verifyCRLVersion(crlToVerify);
                checkCRLvalidatity(crlToVerify);

            }
        } catch (IOException ioException) {
            throwCRLValidationException(ErrorMessages.IO_EXCEPTION, ioException);

        } catch (CRLException crlException) {
            throwCRLValidationException(ErrorMessages.CRL_FORMAT_ERROR, crlException);

        } catch (InvalidKeyException invalidKeyException) {
            throwCRLValidationException(ErrorMessages.INVALID_PUBLIC_KEY, invalidKeyException);

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throwCRLValidationException(ErrorMessages.INVALID_ALGORITHM, noSuchAlgorithmException);

        } catch (NoSuchProviderException noSuchProviderException) {
            throwCRLValidationException(ErrorMessages.NO_SUCH_PROVIDER, noSuchProviderException);

        } catch (SignatureException signatureException) {
            throwCRLValidationException(ErrorMessages.DIGITAL_SIGNATURE_ERROR, signatureException);

        } catch (UnsupportedCRLVersionException unsupportedCRLVersionException) {
            throwCRLValidationException(ErrorMessages.CRL_VERSION_ERROR, unsupportedCRLVersionException);
        }
    }

    private void isCRLIssuerNull(final X509CRL verifyCRL) throws CRLValidationException {
        if (verifyCRL.getIssuerDN() == null) {
            logger.error(ErrorMessages.ISSUER_IS_NULL_IN_CERTIFICATE);
            throw new CRLValidationException(ErrorMessages.ISSUER_IS_NULL_IN_CERTIFICATE);
        }
    }

    private void verifyCRLVersion(final X509CRL verifyCRL) throws UnsupportedCRLVersionException {
        if (verifyCRL.getVersion() != Constants.CRL_VERSION) {
            logger.error(ErrorMessages.CRL_VERSION_ERROR);
            throw new UnsupportedCRLVersionException(ErrorMessages.CRL_VERSION_ERROR);
        }
    }

    private void checkCRLvalidatity(final X509CRL crlToVerify) {
        Date thisUpdate = null;
        Date nextUpdate = null;

        thisUpdate = crlToVerify.getThisUpdate();
        nextUpdate = crlToVerify.getNextUpdate();
        verifyCRLValidity(thisUpdate, nextUpdate);

    }

    private PublicKey getPublicKeyFromTrusts(final String issuerName, final Set<X509Certificate> vendorCertificates, final Set<X509Certificate> caCertificates) throws IOException, KeyStoreException {
        PublicKey caPublicKey = null;
        final Set<X509Certificate> trusts = new HashSet<X509Certificate>();
        if (vendorCertificates != null) {
            trusts.addAll(vendorCertificates);
        }
        trusts.addAll(caCertificates);
        final Iterator<X509Certificate> trustIterator = trusts.iterator();
        while (trustIterator.hasNext()) {
            final X509Certificate issuerCertificate = (X509Certificate) trustIterator.next();
            if (issuerCertificate.getSubjectDN().toString().contains(issuerName)) {
                caPublicKey = issuerCertificate.getPublicKey();
            }
        }
        return caPublicKey;
    }

    private PublicKey getPublicKey(final String issuerName, final Set<X509Certificate> issuerCertificates) throws IOException, KeyStoreException, CRLValidationException {

        PublicKey caPublicKey = null;

        final Set<X509Certificate> trusts = new HashSet<X509Certificate>();
        trusts.addAll(issuerCertificates);

        final Iterator<X509Certificate> trustIterator = trusts.iterator();
        while (trustIterator.hasNext()) {

            final X509Certificate issuerCertificate = (X509Certificate) trustIterator.next();
            if (issuerCertificate.getSubjectDN().toString().contains(issuerName)) {
                caPublicKey = issuerCertificate.getPublicKey();
            }
        }
        if (caPublicKey == null) {
            logger.error(ErrorMessages.CA_NOT_FOUND_FOR_CRL);
            throw new CRLValidationException(ErrorMessages.CA_NOT_FOUND_FOR_CRL);
        }
        return caPublicKey;
    }

    private void verifyCRLDigitalSignature(final X509CRL crl, final PublicKey publicKey) throws CRLException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException {
        crl.verify(publicKey);
    }

    private void verifyCRLValidity(final Date thisUpdate, final Date nextUpdate) {
        final Date currentDate = new Date();
        if (thisUpdate != null) {
            if (!thisUpdate.before(currentDate)) {
                logger.error(ErrorMessages.CRL_THISUPDATE_INVALID);
            }
        }
        if (nextUpdate != null) {
            if (!nextUpdate.after(currentDate)) {
                logger.error(ErrorMessages.CRL_NEXTUPDATE_INVALID);
            }
        }

    }

    private void throwCRLValidationException(final String errorMessage, final Throwable cause) throws CRLValidationException {
        logger.error(errorMessage);
        throw new CRLValidationException(errorMessage, cause);
    }

}
