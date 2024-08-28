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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.vc;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.PKIXCertificatePathBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.*;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateChainCRLValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.CertificateRevokeValidator;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidMessageException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.TrustStoreUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.RequestValidator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util.CRLStore;

/**
 * CRL Validator validates IssuerCRLS and if user certificate or certificates within certificate chain are revoked or not.
 * 
 * @author tcsdemi
 *
 */
public class CRLValidator implements RequestValidator {

    @Inject
    InitialConfiguration configurationData;

    @Inject
    CertificateChainCRLValidator issuerCRLValidator;

    @Inject
    CertificateRevokeValidator isCertificateRevokedValidator;

    @Inject
    PKIXCertificatePathBuilder pKIXCertificatePathBuilder;

    @Inject
    TrustStoreUtil trustStore;

    @Inject
    Logger logger;

    @Inject
    CRLStore crlStore;

    @Override
    public void validate(final RequestMessage pKIRequestMessage) throws CRLValidationException, CertificateRevokedException {

        logger.info("CRL validation started for request Message : {} ", pKIRequestMessage.getRequestMessage());
        try {

            final X509Certificate userCertificate = pKIRequestMessage.getUserCertificate();
            final Set<X509Certificate> certificateChain = pKIRequestMessage.getCertChainSet();

            final Set<X509Certificate> trustedCerts = trustStore.getTrustedCertsBasedOnRequestType(pKIRequestMessage);

            final PKIXCertPathBuilderResult builderResult = pKIXCertificatePathBuilder.build(userCertificate, certificateChain, trustedCerts);
            final Set<X509Certificate> allCertificatesFromCertificatePath = pKIXCertificatePathBuilder.getCertificateChain(builderResult);
            allCertificatesFromCertificatePath.addAll(trustedCerts);

            for (final X509Certificate certificate : allCertificatesFromCertificatePath) {

                final String issuerName = CertificateUtility.getIssuerName(certificate);

                if (issuerName != null) {
                    final X509CRL issuerCRL = crlStore.getCRL(issuerName);
                    if (issuerCRL != null) {
                        issuerCRLValidator.validateIssuerCRL(issuerName, issuerCRL, allCertificatesFromCertificatePath);
                        isCertificateRevokedValidator.validate(certificate, issuerCRL);
                    }
                }
            }

        } catch (KeyStoreException keyStoreException) {
            throw new CRLValidationException(ErrorMessages.INVALID_KEYSTORE, keyStoreException);

        } catch (IOException ioException) {
            throw new CRLValidationException(ErrorMessages.IO_STREAM_COULD_NOT_BE_CLOSED, ioException);

        } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
            throw new CRLValidationException(ErrorMessages.INVALID_ALGORITHM, invalidAlgorithmParameterException);

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new CRLValidationException(ErrorMessages.NO_SUCH_ALGORITHM, noSuchAlgorithmException);

        } catch (CertPathBuilderException certPathBuilderException) {
            throw new CRLValidationException(ErrorMessages.CERTIFICATE_PATH_BUILDER_ERROR, certPathBuilderException);

        } catch (CertificateException certificateException) {
            throw new CRLValidationException(ErrorMessages.CERTIFICATE_EXCEPTION, certificateException);

        } catch (InvalidInitialConfigurationException invalidInitialConfigurationException) {
            throw new CRLValidationException(invalidInitialConfigurationException.getMessage(), invalidInitialConfigurationException);

        } catch (InvalidMessageException invalidMessageException) {
            throw new CRLValidationException(invalidMessageException.getMessage(), invalidMessageException);

        } catch (MessageParsingException messageParsingException) {
            throw new CRLValidationException(messageParsingException.getMessage(), messageParsingException);

        } catch (CertificateParseException certificateParsingException) {
            throw new CRLValidationException(certificateParsingException.getMessage(), certificateParsingException);

        } catch (InvalidCertificateVersionException invalidCertificateVersionException) {
            throw new CRLValidationException(invalidCertificateVersionException.getMessage(), invalidCertificateVersionException);

        } catch (CertificateIsNullException certificateIsNullException) {
            throw new CRLValidationException(certificateIsNullException.getMessage(), certificateIsNullException);

        } catch (CertificateFactoryNotFoundException certificateFactoryNotFoundException) {
            throw new CRLValidationException(certificateFactoryNotFoundException.getMessage(), certificateFactoryNotFoundException);
        }
        logger.info("Successful CRL DONE for request Message : {} ", pKIRequestMessage.getRequestMessage());
    }
}
