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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.GeneralName;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class validates all the fields namely IPAddress,RFC822Name, UniformResourceID,DirectoryName,RegisterID,EDIPartyName,OtherName,DNSName
 * 
 * present in Subject Alternate Name as per RFC standard
 * 
 * @author tcsramc
 *
 */
public class X509CertificateSubjectAltNameValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    SubjectAltNameValidator subjectAltNameValidator;
    public static final int SUBJECT_FIELD_TYPE_INDEX = 0;
    public static final int SUBJECT_FIELD_VALUE_INDEX = 1;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateSAN(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateSAN(final String caName, final X509Certificate x509Certificate) throws InvalidSubjectAltNameExtension {

        try {
            Collection<List<?>> subjectAlternativeNames = null;

            subjectAlternativeNames = x509Certificate.getSubjectAlternativeNames();
            if (subjectAlternativeNames != null) {
                logger.debug("Validate x509 certificate SubjectAltName for CA {}", caName, "{}", subjectAlternativeNames);
                final Iterator<List<?>> subjectAltNameIterator = subjectAlternativeNames.iterator();

                while (subjectAltNameIterator.hasNext()) {
                    final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                    final List subjectAltNameFieldTypes = (List) subjectAltNameIterator.next();

                    final SubjectAltNameFieldType subjectAltNameFieldType = getSANFieldType((int) subjectAltNameFieldTypes.get(SUBJECT_FIELD_TYPE_INDEX));
                    subjectAltNameField.setType(subjectAltNameFieldType);

                    final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
                    subjectAltNameString.setValue(subjectAltNameFieldTypes.get(SUBJECT_FIELD_VALUE_INDEX).toString());

                    subjectAltNameField.setValue(subjectAltNameString);

                    subjectAltNameValidator.validate(subjectAltNameField);
                }
            }
        } catch (CertificateParsingException certificateParsingException) {
            logger.error(ErrorMessages.CERTIFICATE_CONVERSION_ERROR, " for CA {} ", caName, certificateParsingException.getMessage());
            throw new InvalidSubjectAltNameExtension(ErrorMessages.CERTIFICATE_CONVERSION_ERROR, certificateParsingException);
        } catch (InvalidSubjectAltNameExtension invalidSubjectAltNameExtension) {
            logger.error(ErrorMessages.INVALID_SUBJECT_ALT_NAME_EXTENSION, " for CA {} ", caName, invalidSubjectAltNameExtension.getMessage());
            throw new InvalidSubjectAltNameExtension(ErrorMessages.INVALID_SUBJECT_ALT_NAME_EXTENSION, invalidSubjectAltNameExtension);
        }
    }

    private SubjectAltNameFieldType getSANFieldType(final int sanType) throws InvalidSubjectAltNameExtension {
        switch (sanType) {
        case GeneralName.rfc822Name:
            return SubjectAltNameFieldType.RFC822_NAME;
        case GeneralName.dNSName:
            return SubjectAltNameFieldType.DNS_NAME;
        case GeneralName.directoryName:
            return SubjectAltNameFieldType.DIRECTORY_NAME;
        case GeneralName.iPAddress:
            return SubjectAltNameFieldType.IP_ADDRESS;
        case GeneralName.registeredID:
            return SubjectAltNameFieldType.REGESTERED_ID;
        case GeneralName.uniformResourceIdentifier:
            return SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER;
        case GeneralName.ediPartyName:
            return SubjectAltNameFieldType.EDI_PARTY_NAME;
        case GeneralName.otherName:
            return SubjectAltNameFieldType.OTHER_NAME;
        default:
            throw new InvalidSubjectAltNameExtension("SAN FIELD TYPE IS INVALID");
        }
    }
}
