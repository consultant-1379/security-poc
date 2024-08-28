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

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.inject.Inject;
import javax.naming.InvalidNameException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class validates IssuerName Field of X509Certificate as per RFCValidations.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateIssuerNameValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateIssuerName(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateIssuerName(final String caName, final X509Certificate x509Certificate) throws IssuerNotFoundException {
        try {
            final Principal principalIssuerDN = isIssuerDNNull(x509Certificate.getIssuerDN(), caName);
            logger.debug("Validating X509Certificate IssuerName {} for CA", caName, "and issuer principal DN is {}", principalIssuerDN);
            final String countryCode = getCountryCode(principalIssuerDN);
            if (countryCode != null) {
                checkForValidCountryCode(countryCode, caName);
                checkForValidCountryCodeLength(countryCode, caName);
            }
        } catch (InvalidNameException invalidNameException) {
            logger.error(ErrorMessages.INVALID_NAME_FORMAT, "for CA {} ", caName, invalidNameException.getMessage());
            throw new IssuerNotFoundException(ErrorMessages.INVALID_NAME_FORMAT, invalidNameException);
        }
    }

    private Principal isIssuerDNNull(final Principal principalIssuerDN, final String caName) throws IssuerNotFoundException {

        if (principalIssuerDN == null || principalIssuerDN.toString().isEmpty()) {
            logger.error(ErrorMessages.ISSUER_IS_NULL_OR_EMPTY, " for CA {} ", caName);
            throw new IssuerNotFoundException(ErrorMessages.ISSUER_IS_NULL_OR_EMPTY);
        }

        return principalIssuerDN;
    }

    private String getCountryCode(final Principal principalIssuerDN) throws InvalidNameException {
        final String issuerDN = principalIssuerDN.getName();
        final String countryCode = StringUtility.getAttributeValueFromDN(issuerDN, Constants.COUNTRY_CODE_ATTRIBUTE);
        return countryCode;
    }

    private void checkForValidCountryCode(final String countryCode, final String caName) throws IssuerNotFoundException {
        final boolean isValid = isValidCountryCode(countryCode);
        if (!isValid) {
            logger.error(ErrorMessages.INVALID_COUNTRY_CODE + " for CA {} ", caName);
            throw new IssuerNotFoundException(ErrorMessages.INVALID_COUNTRY_CODE);
        }
    }

    private static boolean isValidCountryCode(final String certificateCountryCode) {
        boolean isvalid = false;
        final String[] countryCodes = Locale.getISOCountries();
        for (final String countryCode : countryCodes) {
            if (countryCode.equals(certificateCountryCode)) {
                isvalid = true;
            }
        }
        return isvalid;
    }

    private void checkForValidCountryCodeLength(final String countryCode, final String caName) throws IssuerNotFoundException {
        if (!((countryCode.length()) == 2)) {
            logger.error(ErrorMessages.COUNTRY_CODE_LENGTH_INVALID + " for CA {} ", caName);
            throw new IssuerNotFoundException(ErrorMessages.COUNTRY_CODE_LENGTH_INVALID);
        }
    }
}
