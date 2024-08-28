/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiProfileMapperException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlAccessDescription;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlAccessMethod;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlAuthorityInformationAccess;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlAuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlBasicConstraints;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCRLDistributionPoint;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCRLDistributionPoints;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateExtension;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateExtensions;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateVersion;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlExtendedKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyPurposeId;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlKeyUsageType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlReasonFlag;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectFieldType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlSubjectMapModeller;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessDescription;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityInformationAccess;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifierType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPoint;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

public final class PkiCertificateProfileMapper {

    private PkiCertificateProfileMapper() {
    } //Only static methods

    public static CertificateProfile ConvertCertificateProfileFrom(final XmlCertificateProfile xmlCertificateProfile) throws PkiProfileMapperException {

        final CertificateProfile certificateProfile = new CertificateProfile();

        if (xmlCertificateProfile == null) {
            throw new PkiProfileMapperException("Input parameter is NULL");
        }

        /**
         * CertificateProfile Name
         */

        certificateProfile.setName(xmlCertificateProfile.getName());
        /*
         * The modifiable field is not present on CredetialManagerService XML
         *
         */
        certificateProfile.setModifiable(false);
        /**
         * Certificate extensions
         */

        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();

        final XmlCertificateExtensions xmlCertExts = xmlCertificateProfile.getCertificateExtensions();

        if (xmlCertExts != null) {
            for (final XmlCertificateExtension localXmlCertExt : xmlCertExts.getCertificateExtension()) {

                /**
                 * BasicConstraints.class, AuthorityInformationAccess.class, AuthorityKeyIdentifier.class, SubjectKeyIdentifier.class, SubjectAltName.class, KeyUsage.class, ExtendedKeyUsage.class,
                 * CRLDistributionPoint.class
                 */
                if (localXmlCertExt instanceof XmlExtendedKeyUsage) {
                    final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
                    final List<XmlKeyPurposeId> xmlKeyPurposeIdList = ((XmlExtendedKeyUsage) localXmlCertExt).getKeyPurposeId();
                    final List<KeyPurposeId> keyPurposeIdList = new ArrayList<KeyPurposeId>();
                    for (final XmlKeyPurposeId xmlKeyPurposeId : xmlKeyPurposeIdList) {
                        final KeyPurposeId keyPurposeId = convertKeyPurposeId(xmlKeyPurposeId);
                        keyPurposeIdList.add(keyPurposeId);
                    }

                    extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIdList);

                    if (localXmlCertExt.isCritical() != null) {
                        extendedKeyUsage.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(extendedKeyUsage);

                } else if (localXmlCertExt instanceof XmlBasicConstraints) {
                    final BasicConstraints basicConstraints = new BasicConstraints();

                    basicConstraints.setIsCA(((XmlBasicConstraints) localXmlCertExt).isCA());
                    //basicConstraints.setEnabled(((XmlBasicConstraints) localXmlCertExt).isEnabled());

                    if (((XmlBasicConstraints) localXmlCertExt).getPathLenConstraint() != null) {
                        basicConstraints.setPathLenConstraint(((XmlBasicConstraints) localXmlCertExt).getPathLenConstraint().intValue());
                    }

                    if (localXmlCertExt.isCritical() != null) {
                        basicConstraints.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(basicConstraints);

                } else if (localXmlCertExt instanceof XmlAuthorityInformationAccess) {
                    final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();

                    final List<XmlAccessDescription> xmlAccessDescriptionList = ((XmlAuthorityInformationAccess) localXmlCertExt).getAccessDescription();
                    final List<AccessDescription> accessDescriptionList = new ArrayList<AccessDescription>();

                    for (final XmlAccessDescription xmlAccessDescription : xmlAccessDescriptionList) {

                        final AccessDescription accessDescription = new AccessDescription();

                        if (xmlAccessDescription.getAccessLocation() != null) {
                            accessDescription.setAccessLocation(xmlAccessDescription.getAccessLocation().toString());
                        }

                        accessDescription.setAccessMethod(convertAccessMethod(xmlAccessDescription.getAccessMethod()));
                        accessDescriptionList.add(accessDescription);
                    }

                    authorityInformationAccess.setAccessDescriptions(accessDescriptionList);

                    if (localXmlCertExt.isCritical() != null) {
                        authorityInformationAccess.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(authorityInformationAccess);

                } else if (localXmlCertExt instanceof XmlSubjectKeyIdentifier) {
                    final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
                    final KeyIdentifier keyIdentifier = new KeyIdentifier();
                    final Algorithm algTemp = new Algorithm();
                    algTemp.setName(((XmlSubjectKeyIdentifier) localXmlCertExt).getKeyIdentifierAlgorithm());
                    keyIdentifier.setAlgorithm(algTemp);
                    subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);

                    if (localXmlCertExt.isCritical() != null) {
                        subjectKeyIdentifier.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(subjectKeyIdentifier);

                } else if (localXmlCertExt instanceof XmlSubjectAltName) {
                    final SubjectAltName subjectAltName = new SubjectAltName();
                    final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
                    final List<XmlSubjectAltNameFieldType> xmlSubjectAltNameFieldTypeList = ((XmlSubjectAltName) localXmlCertExt).getSupportedSubjectAltNameField();

                    for (final XmlSubjectAltNameFieldType xmlSubjectAltNameFieldType : xmlSubjectAltNameFieldTypeList) {
                        final SubjectAltNameFieldType subjectAltNameFieldType = convertSubjectAltName(xmlSubjectAltNameFieldType);
                        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                        subjectAltNameField.setType(subjectAltNameFieldType);
                        subjectAltNameFields.add(subjectAltNameField);
                    }

                    subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
                    //subjectAltName.setSupportedSubjectAltNameFieldTypes(subjectAltNameFieldTypeList); //setSupported is no more implemented

                    if (localXmlCertExt.isCritical() != null) {
                        subjectAltName.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(subjectAltName);

                } else if (localXmlCertExt instanceof XmlKeyUsage) {
                    final KeyUsage keyUsage = new KeyUsage();
                    final List<XmlKeyUsageType> xmlKeyUsageTypeList = ((XmlKeyUsage) localXmlCertExt).getKeyUsageType();
                    final List<KeyUsageType> keyUsageTypeList = new ArrayList<KeyUsageType>();

                    for (final XmlKeyUsageType xmlKeyUsageType : xmlKeyUsageTypeList) {
                        final KeyUsageType keyUsageType = convertKeyUsage(xmlKeyUsageType);
                        keyUsageTypeList.add(keyUsageType);
                    }

                    keyUsage.setSupportedKeyUsageTypes(keyUsageTypeList);

                    if (localXmlCertExt.isCritical() != null) {
                        keyUsage.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(keyUsage);

                } else if (localXmlCertExt instanceof XmlCRLDistributionPoints) {
                    final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();

                    final List<DistributionPoint> crlDistributionPointList = new ArrayList<DistributionPoint>();

                    if (((XmlCRLDistributionPoints) localXmlCertExt).getCRLDistributionPoint() != null) {
                        for (final XmlCRLDistributionPoint localXmlCRLDistributionPoint : ((XmlCRLDistributionPoints) localXmlCertExt).getCRLDistributionPoint()) {
                            final DistributionPoint crlDistributionPoint = new DistributionPoint();
                            if (localXmlCRLDistributionPoint.getCRLIssuer() != null) {
                                crlDistributionPoint.setCRLIssuer(localXmlCRLDistributionPoint.getCRLIssuer());
                            }

                            if (localXmlCRLDistributionPoint.getDistributionPointName() != null) {
                                final DistributionPointName distributionPointName = new DistributionPointName();
                                if (localXmlCRLDistributionPoint.getDistributionPointName().getNameRelativeToCRLIssuer() != null) {
                                    distributionPointName.setNameRelativeToCRLIssuer(localXmlCRLDistributionPoint.getDistributionPointName()
                                            .getNameRelativeToCRLIssuer());
                                }
                                if (localXmlCRLDistributionPoint.getDistributionPointName().getFullName() != null) {
                                    distributionPointName.setFullName(localXmlCRLDistributionPoint.getDistributionPointName().getFullName());
                                }
                                crlDistributionPoint.setDistributionPointName(distributionPointName);
                            }
                            if (localXmlCRLDistributionPoint.getReasonFlag() != null) {
                                crlDistributionPoint.setReasonFlag(convertReasonFlag(localXmlCRLDistributionPoint.getReasonFlag()));
                            }
                            crlDistributionPointList.add(crlDistributionPoint);
                        }
                    }
                    crlDistributionPoints.setDistributionPoints(crlDistributionPointList);

                    if (localXmlCertExt.isCritical() != null) {
                        crlDistributionPoints.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(crlDistributionPoints);

                } else if (localXmlCertExt instanceof XmlAuthorityKeyIdentifier) {
                    final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
                    @SuppressWarnings("unused")
                    AuthorityKeyIdentifierType authorityKeyIdentifierType;

                    if (((XmlAuthorityKeyIdentifier) localXmlCertExt).isByAuthorityCertIssuerAndSerialNumber() != null) {
                        authorityKeyIdentifierType = AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER;
                    } else {
                        authorityKeyIdentifierType = AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER;

                    }
                    authorityKeyIdentifier.setType(authorityKeyIdentifierType);
                    if (localXmlCertExt.isCritical() != null) {
                        authorityKeyIdentifier.setCritical(localXmlCertExt.isCritical());
                    }

                    certificateExtensionList.add(authorityKeyIdentifier);
                } else {
                    throw new PkiProfileMapperException("localXmlCertExt not valid instanceof");
                }

            }

            certificateExtensions.setCertificateExtensions(certificateExtensionList);

            certificateProfile.setCertificateExtensions(certificateExtensions);
        }
        /**
         * Key Generation Algorithm
         *
         * OID and AlgorithmType have to be used only for retrieving Algorithms. Do not set...
         *
         */

        final List<XmlAlgorithm> xmlAlgorithmList = xmlCertificateProfile.getKeyGenerationAlgorithm();
        final List<Algorithm> algorithmList = new ArrayList<Algorithm>();
        for (final XmlAlgorithm xmlAlgorithmItem : xmlAlgorithmList) {
            final Algorithm algorithm = new Algorithm();

            if (xmlAlgorithmItem.getKeySize() != null) {
                algorithm.setKeySize(xmlAlgorithmItem.getKeySize().intValue());
            }

            algorithm.setName(xmlAlgorithmItem.getName());
            algorithm.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
            algorithmList.add(algorithm);
        }
        certificateProfile.setKeyGenerationAlgorithms(algorithmList);

        /**
         * SignatureAlgorithm
         */
        final Algorithm algorithm = new Algorithm();
        final XmlAlgorithm xmlAlgorithm = xmlCertificateProfile.getSignatureAlgorithm();

        //algorithm.setKeySize(xmlAlgorithm.getKeySize().intValue());
        algorithm.setName(xmlAlgorithm.getName());
        algorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);

        certificateProfile.setSignatureAlgorithm(algorithm);

        /**
         * IsCAEntity (using setCAEntity)
         */
        certificateProfile.setForCAEntity(xmlCertificateProfile.isIsCAEntity());

        /**
         * Name
         */
        certificateProfile.setName(xmlCertificateProfile.getName());

        /**
         * Issuer
         */
        if (xmlCertificateProfile.getIssuer() != null) {
            if (certificateProfile.getIssuer() == null) {
                final CAEntity entityCATemp = new CAEntity();
                certificateProfile.setIssuer(entityCATemp);
            }
            if (certificateProfile.getIssuer().getCertificateAuthority() == null) {
                final CertificateAuthority caTemp = new CertificateAuthority();
                certificateProfile.getIssuer().setCertificateAuthority(caTemp);
            }

            certificateProfile.getIssuer().getCertificateAuthority().setName(xmlCertificateProfile.getIssuer());
        }
        /**
         * Validity
         */
        certificateProfile.setCertificateValidity(xmlCertificateProfile.getValidity());

        /**
         * Version
         */
        certificateProfile.setVersion(ConvertCertificateVersion(xmlCertificateProfile.getVersion()));

        /**
         * SubjectUniqueIdentifier
         */
        if (xmlCertificateProfile.isSubjectUniqueIdentifier() != null) {
            certificateProfile.setSubjectUniqueIdentifier(xmlCertificateProfile.isSubjectUniqueIdentifier());
        }

        /**
         * IssuerUniqueIdentifier
         */
        if (xmlCertificateProfile.isIssuerUniqueIdentifier() != null) {
            certificateProfile.setIssuerUniqueIdentifier(xmlCertificateProfile.isIssuerUniqueIdentifier());
        }

        /**
         * SkewCertificateTime
         */
        if (xmlCertificateProfile.getSkewCertificateTime() != null) {
            certificateProfile.setSkewCertificateTime(xmlCertificateProfile.getSkewCertificateTime());
        }

        /**
         * SubjectCapabilities
         */

        if (xmlCertificateProfile.getSubjectCapabilities() != null) {
            final List<XmlSubjectMapModeller.XmlSubjectEntry> xmlsubjectenty = xmlCertificateProfile.getSubjectCapabilities().getSubjectDN().getSubjectEntry();
            final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();

            for (final XmlSubjectMapModeller.XmlSubjectEntry xmlsubjectentry : xmlsubjectenty) {
                subjectMap.put(convertSubjectFieldType(xmlsubjectentry.getType()), xmlsubjectentry.getValue());
            }

            final Subject pkiSubject = new Subject();
            for (final Entry<SubjectFieldType, String> entry : subjectMap.entrySet()) {
                final SubjectField subjFieldTemp = new SubjectField();
                subjFieldTemp.setValue(entry.getValue());
                subjFieldTemp.setType(entry.getKey());
                pkiSubject.getSubjectFields().add(subjFieldTemp);
            }

            certificateProfile.setSubjectCapabilities(pkiSubject);
        }

        else { //Pki does not accept null subject capabilities

            final Subject pkiSubject = new Subject();

            final List<SubjectField> subjectfieldlist = new ArrayList<SubjectField>();
            final SubjectField subfieldCN = new SubjectField();
            final SubjectField subfieldCoN = new SubjectField();
            final SubjectField subfieldDN = new SubjectField();
            final SubjectField subfieldGN = new SubjectField();
            final SubjectField subfieldLN = new SubjectField();
            final SubjectField subfieldO = new SubjectField();
            final SubjectField subfieldOU = new SubjectField();
            final SubjectField subfieldSN = new SubjectField();
            final SubjectField subfieldST = new SubjectField();
            final SubjectField subfieldSA = new SubjectField();
            final SubjectField subfieldSU = new SubjectField();
            final SubjectField subfieldT = new SubjectField();

            subfieldCN.setType(SubjectFieldType.COMMON_NAME);
            subfieldCoN.setType(SubjectFieldType.COUNTRY_NAME);
            subfieldDN.setType(SubjectFieldType.DN_QUALIFIER);
            subfieldGN.setType(SubjectFieldType.GIVEN_NAME);
            subfieldLN.setType(SubjectFieldType.LOCALITY_NAME);
            subfieldO.setType(SubjectFieldType.ORGANIZATION);
            subfieldOU.setType(SubjectFieldType.ORGANIZATION_UNIT);
            subfieldSN.setType(SubjectFieldType.SERIAL_NUMBER);
            subfieldST.setType(SubjectFieldType.STATE);
            subfieldSA.setType(SubjectFieldType.STREET_ADDRESS);
            subfieldSU.setType(SubjectFieldType.SURNAME);
            subfieldT.setType(SubjectFieldType.TITLE);

            subjectfieldlist.add(subfieldCN);
            subjectfieldlist.add(subfieldCoN);
            subjectfieldlist.add(subfieldDN);
            subjectfieldlist.add(subfieldGN);
            subjectfieldlist.add(subfieldLN);
            subjectfieldlist.add(subfieldO);
            subjectfieldlist.add(subfieldOU);
            subjectfieldlist.add(subfieldSN);
            subjectfieldlist.add(subfieldST);
            subjectfieldlist.add(subfieldSA);
            subjectfieldlist.add(subfieldSU);
            subjectfieldlist.add(subfieldT);

            pkiSubject.setSubjectFields(subjectfieldlist);
            certificateProfile.setSubjectCapabilities(pkiSubject);

        }

        return certificateProfile;
    }

    /**
     * @param version
     * @return
     * @throws PkiProfileMapperException
     */
    private static CertificateVersion ConvertCertificateVersion(final XmlCertificateVersion version) throws PkiProfileMapperException {
        switch (version) {

        case V_3:
            return CertificateVersion.V3;
        default:
            throw new PkiProfileMapperException("Unexpected XmlCertificateVersion value to convert");
        }
    }

    /**
     * @param xmlKeyUsageType
     * @return
     * @throws PkiProfileMapperException
     */
    private static KeyUsageType convertKeyUsage(final XmlKeyUsageType xmlKeyUsageType) throws PkiProfileMapperException {

        switch (xmlKeyUsageType) {
        case DIGITAL_SIGNATURE:
            return KeyUsageType.DIGITAL_SIGNATURE;
        case NON_REPUDIATION:
            return KeyUsageType.NON_REPUDIATION;
        case KEY_ENCIPHERMENT:
            return KeyUsageType.KEY_ENCIPHERMENT;
        case DATA_ENCIPHERMENT:
            return KeyUsageType.DATA_ENCIPHERMENT;
        case KEY_AGREEMENT:
            return KeyUsageType.KEY_AGREEMENT;
        case KEY_CERT_SIGN:
            return KeyUsageType.KEY_CERT_SIGN;
        case CRL_SIGN:
            return KeyUsageType.CRL_SIGN;
        case ENCIPHER_ONLY:
            return KeyUsageType.ENCIPHER_ONLY;
        case DECIPHER_ONLY:
            return KeyUsageType.DECIPHER_ONLY;
        default:
            throw new PkiProfileMapperException("Unexpected XmlKeyUsageType value to convert");
        }
    }

    /**
     * @param accessMethod
     * @return
     * @throws PkiProfileMapperException
     */
    private static AccessMethod convertAccessMethod(final XmlAccessMethod xmlAccessMethod) throws PkiProfileMapperException {

        switch (xmlAccessMethod) {
        case CA_ISSUER:
            return AccessMethod.CA_ISSUER;
        case OCSP:
            return AccessMethod.OCSP;
        default:
            throw new PkiProfileMapperException("Unexpected XmlAccessMethod value to convert");
        }
    }

    /**
     * @param xmlKeyPurposeId
     * @return
     * @throws PkiProfileMapperException
     */
    private static KeyPurposeId convertKeyPurposeId(final XmlKeyPurposeId xmlKeyPurposeId) throws PkiProfileMapperException {

        switch (xmlKeyPurposeId) {
        case ANY_EXTENDED_KEY_USAGE:
            return KeyPurposeId.ANY_EXTENDED_KEY_USAGE;
        case ID_KP_CLIENT_AUTH:
            return KeyPurposeId.ID_KP_CLIENT_AUTH;
        case ID_KP_CODE_SIGNING:
            return KeyPurposeId.ID_KP_CODE_SIGNING;
        case ID_KP_EMAIL_PROTECTION:
            return KeyPurposeId.ID_KP_EMAIL_PROTECTION;
        case ID_KP_TIMESTAMPING:
            return KeyPurposeId.ID_KP_TIME_STAMPING;
        case ID_KP_OCSP_SIGNING:
            return KeyPurposeId.ID_KP_OCSP_SIGNING;
        case ID_KP_SERVER_AUTH:
            return KeyPurposeId.ID_KP_SERVER_AUTH;
        default:
            throw new PkiProfileMapperException("Unexpected XmlKeyPurposeId value to convert");
        }
    }

    private static SubjectFieldType convertSubjectFieldType(final XmlSubjectFieldType type) throws PkiProfileMapperException {

        switch (type) {
        case COMMON_NAME:
            return SubjectFieldType.COMMON_NAME;
        case SURNAME:
            return SubjectFieldType.SURNAME;
        case COUNTRY_NAME:
            return SubjectFieldType.COUNTRY_NAME;
        case LOCALITY_NAME:
            return SubjectFieldType.LOCALITY_NAME;
        case STATE:
            return SubjectFieldType.STATE;
        case STREET_ADDRESS:
            return SubjectFieldType.STREET_ADDRESS;
        case ORGANIZATION:
            return SubjectFieldType.ORGANIZATION;
        case ORGANIZATION_UNIT:
            return SubjectFieldType.ORGANIZATION_UNIT;
        case DN_QUALIFIER:
            return SubjectFieldType.DN_QUALIFIER;
        case TITLE:
            return SubjectFieldType.TITLE;
        case GIVEN_NAME:
            return SubjectFieldType.GIVEN_NAME;
        case SERIAL_NUMBER:
            return SubjectFieldType.SERIAL_NUMBER;
        default:
            throw new PkiProfileMapperException("Unexpected XmlSubjectFieldType value to convert");
        }
    }

    private static SubjectAltNameFieldType convertSubjectAltName(final XmlSubjectAltNameFieldType xmlType) throws PkiProfileMapperException {

        switch (xmlType) {
        case RFC_822_NAME:
            return SubjectAltNameFieldType.RFC822_NAME;
        case OTHER_NAME:
            return SubjectAltNameFieldType.OTHER_NAME;
        case EDI_PARTY_NAME:
            return SubjectAltNameFieldType.EDI_PARTY_NAME;
        case DNS_NAME:
            return SubjectAltNameFieldType.DNS_NAME;
            //        case X_400_ADDRESS:
            //            return SubjectAltNameFieldType.X400_ADDRESS;
        case DIRECTORY_NAME:
            return SubjectAltNameFieldType.DIRECTORY_NAME;
        case UNIFORM_RESOURCE_IDENTIFIER:
            return SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER;
        case IP_ADDRESS:
            return SubjectAltNameFieldType.IP_ADDRESS;
        case REGESTERED_ID:
            return SubjectAltNameFieldType.REGESTERED_ID;
        default:
            throw new PkiProfileMapperException("Unexpected XmlSubjectAltNameFieldType value to convert");
        }

    }

    private static ReasonFlag convertReasonFlag(final XmlReasonFlag xmlReasonFlag) throws PkiProfileMapperException {

        switch (xmlReasonFlag) {
        case AA_COMPROMISE:
            return ReasonFlag.AA_COMPROMISE;
        case CA_COMPROMISE:
            return ReasonFlag.CA_COMPROMISE;
        case AFFILIATION_CHANGED:
            return ReasonFlag.AFFILIATION_CHANGED;
        case CERTIFICATE_HOLD:
            return ReasonFlag.CERTIFICATE_HOLD;
        case CESSATION_OF_OPERATION:
            return ReasonFlag.CESSATION_OF_OPERATION;
        case KEY_COMPROMISE:
            return ReasonFlag.KEY_COMPROMISE;
        case PRIVILEGE_WITHDRAWN:
            return ReasonFlag.PRIVILEGE_WITHDRAWN;
        case SUPERSEDED:
            return ReasonFlag.SUPERSEDED;
        case UNUSED:
            return ReasonFlag.UNUSED;
        default:
            throw new PkiProfileMapperException("Unexpected XmlSubjectAltNameFieldType value to convert");
        }

    }

}
