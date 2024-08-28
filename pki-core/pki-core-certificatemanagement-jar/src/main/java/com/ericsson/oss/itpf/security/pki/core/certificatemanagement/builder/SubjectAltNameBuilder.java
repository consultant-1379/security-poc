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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidSubjectAltNameException;

/**
 * This class builds SubjectAltName extension for the certificate.
 * 
 */
public class SubjectAltNameBuilder {

    @Inject
    CertificateGenerationInfoParser certificateGenerationInfoParser;
    @Inject
    Logger logger;

    /**
     * Builds {@link SubjectAltNameValues} from certificate extension passed.
     * 
     * @param certificateExtension
     *            CertificateExtension that to be built as {@link SubjectAltName}
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} which has subject alt name fields and values.
     * @return Extension that has {@link SubjectAltName} object.
     * @throws InvalidSubjectAltNameException
     *             Thrown in case if any failures occur in building extension.
     */
    public Extension buildSubjectAltName(final CertificateExtension certificateExtension, final CertificateGenerationInfo certificateGenerationInfo) throws InvalidSubjectAltNameException {

        Extension extension = null;
        final SubjectAltName subjectAltName = certificateGenerationInfoParser.getSubjectAltNameFromCertGenerationInfo(certificateGenerationInfo);

        if (subjectAltName != null) {
            logger.debug("Adding SubjectAltName Extension to the Certificate {}", subjectAltName);

            logger.debug("Critical flag for SAN set to {} ", subjectAltName.isCritical());

            final List<GeneralName> subjectAltNames = getSubjectAltNames(subjectAltName.getSubjectAltNameFields());
            try {
                final DEROctetString subjectAltNameExtension = new DEROctetString(new GeneralNames(subjectAltNames.toArray(new GeneralName[0])));
                extension = new Extension(Extension.subjectAlternativeName, certificateExtension.isCritical(), subjectAltNameExtension);
                return extension;

            } catch (IOException ioException) {
                logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
                throw new InvalidSubjectAltNameException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
            }
        } else {
            return null;
        }

    }

    private List<GeneralName> getSubjectAltNames(final List<SubjectAltNameField> subjectAltNameFields) {

        final List<GeneralName> generalNameList = new ArrayList<>();

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFields) {
            addSANValue(generalNameList, subjectAltNameField);
        }
        logger.debug("List of GeneralNames added for SubjectAltName {} ", generalNameList);

        return generalNameList;
    }

    private int getSANFieldType(final SubjectAltNameFieldType type) throws InvalidSubjectAltNameException {
        switch (type) {
        case RFC822_NAME:
            return GeneralName.rfc822Name;
        case DNS_NAME:
            return GeneralName.dNSName;
        case DIRECTORY_NAME:
            return GeneralName.directoryName;
        case IP_ADDRESS:
            return GeneralName.iPAddress;
        case REGESTERED_ID:
            return GeneralName.registeredID;
        case UNIFORM_RESOURCE_IDENTIFIER:
            return GeneralName.uniformResourceIdentifier;
        case EDI_PARTY_NAME:
            return GeneralName.ediPartyName;
        case OTHER_NAME:
            return GeneralName.otherName;
        default:
            throw new InvalidSubjectAltNameException(ErrorMessages.INVALID_SANFIELD_TYPE);
        }
    }

    private static byte[] ipStringToOctets(final String str) {
        final String[] toks = str.split("[.:]");
        if (toks.length == 4) {
            // IPv4 address such as 192.168.5.45
            final byte[] ret = new byte[4];
            for (int i = 0; i < toks.length; i++) {
                final int t = Integer.parseInt(toks[i]);
                if (t > 255) {
                    return null;
                }
                ret[i] = (byte) t;
            }
            return ret;
        }
        if (toks.length == 8) {
            // IPv6 address such as 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            final byte[] ret = new byte[16];
            int ind = 0;
            for (int i = 0; i < toks.length; i++) {
                final int t = Integer.parseInt(toks[i], 16);
                if (t > 0xFFFF) {
                    return null;
                }
                final int t1 = t >> 8;
                final int b1 = t1 & 0x00FF;
                // int b1 = t & 0x00FF;
                ret[ind++] = (byte) b1;
                // int b2 = t & 0xFF00;
                final int b2 = t & 0x00FF;
                ret[ind++] = (byte) b2;
            }
            return ret;
        }
        return new byte[0];
    }

    private ASN1Encodable getSANFieldValue(final SubjectAltNameFieldType type, final AbstractSubjectAltNameFieldValue abstractSubjectAltNameFieldValue) throws InvalidSubjectAltNameException {

        switch (type) {
        case RFC822_NAME:
        case DNS_NAME:
        case EDI_PARTY_NAME:
        case UNIFORM_RESOURCE_IDENTIFIER:
            return new DERIA5String(abstractSubjectAltNameFieldValue.toString());
        case DIRECTORY_NAME:
            return new X500Name(abstractSubjectAltNameFieldValue.toString());
        case IP_ADDRESS:
            return new DEROctetString(ipStringToOctets(abstractSubjectAltNameFieldValue.toString()));
        case REGESTERED_ID:
            return ASN1ObjectIdentifier.getInstance(abstractSubjectAltNameFieldValue.toString());
        case OTHER_NAME:
            return new DERUTF8String(abstractSubjectAltNameFieldValue.toString());
        default:
            throw new InvalidSubjectAltNameException(ErrorMessages.INVALID_SANFIELD_TYPE);
        }
    }

    private void addSANValue(final List<GeneralName> generalNameList, final SubjectAltNameField subjectAltNameField) throws InvalidSubjectAltNameException {

        final SubjectAltNameFieldType sANFieldType = subjectAltNameField.getType();

        final AbstractSubjectAltNameFieldValue sANValue = subjectAltNameField.getValue();
        final GeneralName generalName = new GeneralName(getSANFieldType(sANFieldType), getSANFieldValue(subjectAltNameField.getType(), sANValue));
        generalNameList.add(generalName);
    }
}
