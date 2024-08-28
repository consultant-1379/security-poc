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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;

/**
 * Class for parsing PKCS#10 request.
 *
 * <p>
 * This class used to parse the PKCS10 request and extract key generation algorithm, subject alt name values and challenge password.
 * </p>
 */
public class CertificateRequestParser {

    @Inject
    static Logger logger;

    // TODO Make use of sub classes here each specialized in extracting the specific information, this comment will be addressed as part of TORF-54827

    private CertificateRequestParser() {

    }

    /**
     * Retrieve SubjectAltName from CertificateRequest which contains either PKCS10/CRMF Request.
     *
     * @param certificateRequest
     *            The CertificateRequest request object containing either PKCS10/CRMF request.
     *
     * @return SubjectAltName object.
     */
    public static SubjectAltName extractSubjectAltName(final CertificateRequest certificateRequest) {

        final Extensions extensions = getExtensions(certificateRequest);

        if (extensions == null) {
            return null;
        }

        final GeneralNames generalNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        final GeneralName[] names = generalNames.getNames();

        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        buildSubjectAltNameFields(subjectAltNameFields, names);

        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    /**
     * Retrieve Extensions from CertificateRequest
     *
     * @param certificateRequest
     *            The CertificateRequest request object.
     *
     * @return Extensions object.
     */
    private static Extensions getExtensions(final CertificateRequest certificateRequest) {

        Extensions extensions = null;

        if (certificateRequest.getCertificateRequestHolder() != null) {
            if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
                final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder();
                final PKCS10CertificationRequest pKCS10CertificationRequest = pkcs10CertificationRequestHolder.getCertificateRequest();
                extensions = getExtensionsFromPKCS10Request(pKCS10CertificationRequest, extensions);
            }

            else {
                final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
                final CertificateRequestMessage certificateRequestMessage = crmfRequestHolder.getCertificateRequest();
                extensions = certificateRequestMessage.getCertTemplate().getExtensions();
            }
        }
        return extensions;
    }

    private static Extensions getExtensionsFromPKCS10Request(final PKCS10CertificationRequest pKCS10CertificationRequest, Extensions extensions) {

        final Attribute[] csrAttributes = pKCS10CertificationRequest.getAttributes();
        for (final Attribute attribute : csrAttributes) {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                break;
            }
        }
        return extensions;
    }

    private static void buildSubjectAltNameFields(final List<SubjectAltNameField> subjectAltNameFields, final GeneralName[] names) {

        for (int k = 0; k < names.length; k++) {
            switch (names[k].getTagNo()) {
            case GeneralName.dNSName:
                setSANStringValueByType(subjectAltNameFields, SubjectAltNameFieldType.DNS_NAME, names[k].getName().toString());
                break;
            case GeneralName.directoryName:
                setSANStringValueByType(subjectAltNameFields, SubjectAltNameFieldType.DIRECTORY_NAME, names[k].getName().toString());
                break;
            case GeneralName.iPAddress:
                final String ipAddress = getIPAddress(names[k]);
                setSANStringValueByType(subjectAltNameFields, SubjectAltNameFieldType.IP_ADDRESS, ipAddress);
                break;
            case GeneralName.registeredID:
                setSANStringValueByType(subjectAltNameFields, SubjectAltNameFieldType.REGESTERED_ID, names[k].getName().toString());
                break;
            case GeneralName.rfc822Name:
                setSANStringValueByType(subjectAltNameFields, SubjectAltNameFieldType.RFC822_NAME, names[k].getName().toString());
                break;
            case GeneralName.uniformResourceIdentifier:
                setSANStringValueByType(subjectAltNameFields, SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER, names[k].getName().toString());
                break;
            case GeneralName.otherName:
                setSANOtherNameValue(subjectAltNameFields, names[k]);
                break;
            case GeneralName.ediPartyName:
                setSANEdiPartyName(subjectAltNameFields, names[k]);
                break;
            }
        }
    }

    private static void setSANEdiPartyName(final List<SubjectAltNameField> subjectAltNameFields, final GeneralName name) {

        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final EdiPartyName ediPartyName = new EdiPartyName();
        ediPartyName.setPartyName(name.getName().toString());
        subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameField.setValue(ediPartyName);
        subjectAltNameFields.add(subjectAltNameField);
    }

    private static void setSANOtherNameValue(final List<SubjectAltNameField> subjectAltNameFields, final GeneralName name) {

        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final OtherName otherName = new OtherName();
        otherName.setValue(name.getName().toString());
        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameField.setValue(otherName);
        subjectAltNameFields.add(subjectAltNameField);

    }

    private static String getIPAddress(final GeneralName name) {

        InetAddress inetAddress = null;
        String ipAddress = null;
        try {
            inetAddress = InetAddress.getByAddress(DatatypeConverter.parseHexBinary(name.getName().toString().substring(1)));
            ipAddress = inetAddress.toString().substring(1);

        } catch (final UnknownHostException unknownHostException) {
            logger.error("Invalid IPAddress  " + ipAddress, unknownHostException);
            throw new CertificateGenerationException("Invalid IPAddress " + ipAddress, unknownHostException);
        }
        return ipAddress;

    }

    private static void setSANStringValueByType(final List<SubjectAltNameField> subjectAltNameFields, final SubjectAltNameFieldType sANFieldType, final String generalName) {

        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(generalName);
        subjectAltNameField.setType(sANFieldType);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameFields.add(subjectAltNameField);
    }

    /**
     * Check PKCS10CertificationRequest contains subjectAltName values.
     * 
     * @param pKCS10CertificationRequest
     *            The pkcs10 request object.
     * 
     * @return true if pkcs10 request contains subjectAltName fields else false.
     */
    public static boolean checkForSubjectAltName(final PKCS10CertificationRequest pKCS10CertificationRequest) {
        final Attribute[] certAttributes = pKCS10CertificationRequest.getAttributes();
        for (final Attribute attribute : certAttributes) {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                final Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                final GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                if (gns.getNames().length > 0) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check whether CRMF Request contains subjectAltName values.
     * 
     * @param certificateRequestMessage
     *            The CertificateRequestMessage object.
     * 
     * @return true if CRMF request contains subjectAltName fields else false.
     */
    public static boolean checkForSubjectAltName(final CertificateRequestMessage certificateRequestMessage) {
        final Extensions extensions = certificateRequestMessage.getCertTemplate().getExtensions();
        if (extensions == null) {
            return false;
        }
        final GeneralNames generalName = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (generalName.getNames().length > 0) {
            return true;
        }
        return false;
    }

    /**
     * Method to extract the key generation algorithm from the given certificate request.
     *
     * @param certificateRequest
     *            The CertificateRequest object.
     * @return key generation algorithm name.
     *
     * @throws AlgorithmNotFoundException
     *            is thrown when the given algorithm is not supported.
     *
     */

    public static String extractKeyGenerationAlgorithm(final CertificateRequest certificateRequest) throws AlgorithmNotFoundException {

        SubjectPublicKeyInfo subjectPublicKeyInfo = null;
        if (certificateRequest.getCertificateRequestHolder() != null) {

            if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
                subjectPublicKeyInfo = ((PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder()).getCertificateRequest().getSubjectPublicKeyInfo();
            } else {
                subjectPublicKeyInfo = ((CRMFRequestHolder) certificateRequest.getCertificateRequestHolder()).getCertificateRequest().getCertTemplate().getPublicKey();
            }
        }

        if (subjectPublicKeyInfo == null) {
            return null;
        }

        final AlgorithmIdentifier algorithmIdentifier = subjectPublicKeyInfo.getAlgorithm();
        final DefaultAlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();
        String algorithmName = algorithmNameFinder.getAlgorithmName(algorithmIdentifier);
        if (algorithmName != (Constants.RSA_ALGORITHM_NAME)) {
            try {
                final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                final PublicKey pubKeyStruct = converter.getPublicKey(subjectPublicKeyInfo);
                if (pubKeyStruct instanceof ECPublicKey) {
                    final ASN1ObjectIdentifier curveOID = (ASN1ObjectIdentifier) algorithmIdentifier.getParameters();
                    if (curveOID != null && (curveOID.toString().equals(Constants.SECP256R1_OID)
                            || curveOID.toString().equals(Constants.SECP384R1_OID) || curveOID.toString().equals(Constants.SECP521R1_OID))) {
                        algorithmName = Constants.ECDSA_ALGORITHM_NAME;
                    } else {
                        throw new AlgorithmNotFoundException("Curve OID " + curveOID
                                + " doesn't exist in the list of supported Elliptic curves. Use a valid EC curve either secp256r1 (1.2.840.10045.3.1.7), secp384r1 (1.3.132.0.34) or secp521r1 (1.3.132.0.35) to generate key pair as part of CSR generation");
                    }
                } else {
                    throw new AlgorithmNotFoundException("Algorithm should be RSA or ECDSA");
                }
            } catch (final PEMException exception) {
                final String errorMessage =  "Unable to parse the public key from the CSR. The error is caused due to : "+ exception.getMessage();
                throw new AlgorithmNotFoundException(errorMessage);
            }
        }
        return algorithmName;
    }

}
