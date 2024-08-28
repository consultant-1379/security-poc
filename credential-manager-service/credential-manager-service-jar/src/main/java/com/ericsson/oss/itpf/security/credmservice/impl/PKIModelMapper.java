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
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

//import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAccessDescription;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAccessMethod;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithmType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAuthorityInformationAccess;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerBasicConstraints;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLDistributionPoint;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLDistributionPoints;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateExtensions;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerDistributionPointName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEdiPartyName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityCertificates;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerExtendedKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyPurposeId;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyUsageType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerOtherName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerReasonFlag;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.api.model.exception.CRLEncodingException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
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
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public final class PKIModelMapper {

    private PKIModelMapper() {
    };

    public static CredentialManagerEntity credMEndEntityFrom(final Entity ee) throws CredentialManagerInvalidEntityException {
        if (ee == null) {
            throw new CredentialManagerInvalidEntityException("End Entity is null");
        }

        final CredentialManagerEntity ret = new CredentialManagerEntity();

        credMEntityFrom(ee, ret);

        return ret;
    }

    public static CredentialManagerEntity credMEndEntitySummaryFrom(final Entity ee) throws CredentialManagerInvalidEntityException {
        if (ee == null) {
            throw new CredentialManagerInvalidEntityException("End Entity is null");
        }

        final CredentialManagerEntity ret = new CredentialManagerEntity();

        credMEntitySummaryFrom(ee, ret);

        return ret;
    }

    private static void credMEntityFrom(final Entity ee, final CredentialManagerEntity ret) {
        ret.setSubject(credMSubjectFrom(ee.getEntityInfo().getSubject()));
        ret.setSubjectAltName(credMSubjectAltNameFrom(ee.getEntityInfo().getSubjectAltName()));
        if (ee.getEntityInfo().getIssuer() != null) {
            ret.setIssuerDN(credMSubjectFrom(ee.getEntityInfo().getIssuer().getSubject()));
        }
        ret.setEntityProfileName(ee.getEntityProfile().getName());
        ret.setName(ee.getEntityInfo().getName());
        ret.setId(ee.getEntityInfo().getId());
        ret.setEntityStatus(CredentialManagerEntityStatus.fromValue((ee.getEntityInfo().getStatus().toString())));
        ret.setEntityType(CredentialManagerEntityType.fromString((ee.getType().toString())));
        ret.setKeyGenerationAlgorithm(credMAlgorithmFrom(ee.getKeyGenerationAlgorithm()));
    }

    private static void credMEntitySummaryFrom(final Entity ee, final CredentialManagerEntity ret) {
        ret.setSubject(credMSubjectFrom(ee.getEntityInfo().getSubject()));
        ret.setName(ee.getEntityInfo().getName());
        ret.setEntityStatus(CredentialManagerEntityStatus.fromValue((ee.getEntityInfo().getStatus().toString())));
    }

    public static CredentialManagerEntityCertificates credMEndEntityCertificatesFrom(final Entity ee)
            throws CredentialManagerInvalidEntityException, CredentialManagerCertificateEncodingException {
        final CredentialManagerEntityCertificates ret = new CredentialManagerEntityCertificates();
        credMEntityFrom(ee, ret);

        final Certificate activeCertificate = ee.getEntityInfo().getActiveCertificate();
        if (activeCertificate != null) {
            ret.getCerts().add(credMCertificateFrom(activeCertificate));
        }
        for (final Certificate inactiveCertificate : ee.getEntityInfo().getInActiveCertificates()) {
            ret.getCerts().add(credMCertificateFrom(inactiveCertificate));
        }

        return ret;
    }

    public static CredentialManagerProfileInfo credMProfileInfoFrom(final EntityProfile pkiEntityProfile, final CertificateProfile pkiCertProfile)
            throws CredentialManagerInvalidProfileException {

        if (pkiEntityProfile == null) {
            throw new CredentialManagerInvalidProfileException("pki Entity Profile is null");
        }

        if (pkiCertProfile == null) {
            throw new CredentialManagerInvalidProfileException("pki Certificate Profile is null");
        }

        final CredentialManagerProfileInfo profileInfo = new CredentialManagerProfileInfo();

        profileInfo.setIssuerName(pkiCertProfile.getIssuer().getCertificateAuthority().getName());
        if (pkiEntityProfile.getKeyGenerationAlgorithm() != null) {
            profileInfo.setKeyPairAlgorithm(credMAlgorithmFrom(pkiEntityProfile.getKeyGenerationAlgorithm()));
        }

        profileInfo.setSignatureAlgorithm(credMAlgorithmFrom(pkiCertProfile.getSignatureAlgorithm()));

        profileInfo.setSubjectByProfile(credMSubjectFrom(pkiEntityProfile.getSubject()));

        profileInfo.setSubjectDefaultAlternativeName(credMSubjectAltNameFrom(pkiEntityProfile.getSubjectAltNameExtension()));

        profileInfo.setExtentionAttributes(
                credMExtensionFrom(pkiCertProfile.getCertificateExtensions(), pkiEntityProfile.getCertificateProfile().getCertificateExtensions()));

        return profileInfo;
    }

    /**
     * @param subjectAltName
     * @return
     */
    public static CredentialManagerSubjectAltName credMSubjectAltNameFrom(final SubjectAltName subjectAltName) {
        final CredentialManagerSubjectAltName ret = new CredentialManagerSubjectAltName();

        if (subjectAltName == null) {
            return null;
        }
        if (subjectAltName.getSubjectAltNameFields() != null) {

            for (final SubjectAltNameField entry : subjectAltName.getSubjectAltNameFields()) {
                final List values = new ArrayList();
                final AbstractSubjectAltNameFieldValue value = entry.getValue();
                if (value.getClass() == EdiPartyName.class) {
                    final EdiPartyName pkiEdiParty = (EdiPartyName) value;
                    final CredentialManagerEdiPartyName ediParty = new CredentialManagerEdiPartyName();
                    ediParty.setNameAssigner(pkiEdiParty.getNameAssigner());
                    ediParty.setPartyName(pkiEdiParty.getPartyName());
                    values.add(ediParty);
                }
                if (value.getClass() == OtherName.class) {
                    final OtherName pkiOtherName = (OtherName) value;
                    final CredentialManagerOtherName otherName = new CredentialManagerOtherName();
                    otherName.setTypeId(pkiOtherName.getTypeId());
                    otherName.setValue(pkiOtherName.getValue());
                    values.add(otherName);
                }
                if (value.getClass() == SubjectAltNameString.class) {
                    final SubjectAltNameString pkiSubjectAltNameString = (SubjectAltNameString) value;
                    final String subjectAltNameString = pkiSubjectAltNameString.getValue();
                    values.add(subjectAltNameString);
                }

                if (entry.getType() == SubjectAltNameFieldType.DIRECTORY_NAME) {
                    ret.setDirectoryName(values);
                } else if (entry.getType() == SubjectAltNameFieldType.DNS_NAME) {
                    ret.setDNSName(values);
                } else if (entry.getType() == SubjectAltNameFieldType.EDI_PARTY_NAME) {
                    ret.setEdiPartyName(values);
                } else if (entry.getType() == SubjectAltNameFieldType.IP_ADDRESS) {
                    ret.setIPAddress(values);
                } else if (entry.getType() == SubjectAltNameFieldType.OTHER_NAME) {
                    ret.setOtherName(values);
                } else if (entry.getType() == SubjectAltNameFieldType.REGESTERED_ID) {
                    ret.setRegisteredID(values);
                } else if (entry.getType() == SubjectAltNameFieldType.RFC822_NAME) {
                    ret.setRfc822Name(values);
                } else if (entry.getType() == SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER) {
                    ret.setUniformResourceIdentifier(values);
                }
                //                else if (entry.getType() == SubjectAltNameFieldType.X400_ADDRESS) {
                //                    ret.setX400Address(values);
                //                }

            }
        }

        return ret;
    }

    private static List<AbstractSubjectAltNameFieldValue> pkiSubjectAltNameStringValuesFrom(final List<String> credMStringValue) {
        final List<AbstractSubjectAltNameFieldValue> values = new ArrayList<AbstractSubjectAltNameFieldValue>();
        for (final String value : credMStringValue) {
            final SubjectAltNameString pkiSubjectAltNameString = new SubjectAltNameString();
            pkiSubjectAltNameString.setValue(value);
            values.add(pkiSubjectAltNameString);
        }
        return values;
    }

    public static SubjectAltName pkiSubjectAltNameFrom(final CredentialManagerSubjectAltName subjectAltName) {

        final SubjectAltName ret = new SubjectAltName();
        if (subjectAltName == null) {
            return null;
        }
        final List<SubjectAltNameField> subjectAltNameFieldList = new ArrayList<SubjectAltNameField>();

        final List<AbstractSubjectAltNameFieldValue> directoryNames = pkiSubjectAltNameStringValuesFrom(subjectAltName.getDirectoryName());
        if (!directoryNames.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : directoryNames) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }

        final List<AbstractSubjectAltNameFieldValue> dnsNames = pkiSubjectAltNameStringValuesFrom(subjectAltName.getDNSName());
        if (!dnsNames.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : dnsNames) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.DNS_NAME);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }
        final List<AbstractSubjectAltNameFieldValue> ipAddresses = pkiSubjectAltNameStringValuesFrom(subjectAltName.getIPAddress());
        if (!ipAddresses.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : ipAddresses) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }
        final List<AbstractSubjectAltNameFieldValue> registeredIds = pkiSubjectAltNameStringValuesFrom(subjectAltName.getRegisteredID());
        if (!registeredIds.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : registeredIds) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.REGESTERED_ID);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }
        final List<AbstractSubjectAltNameFieldValue> rfc822Names = pkiSubjectAltNameStringValuesFrom(subjectAltName.getRfc822Name());
        if (!rfc822Names.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : rfc822Names) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.RFC822_NAME);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }
        final List<AbstractSubjectAltNameFieldValue> uniformResourceIdentifiers = pkiSubjectAltNameStringValuesFrom(
                subjectAltName.getUniformResourceIdentifier());
        if (!uniformResourceIdentifiers.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : uniformResourceIdentifiers) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }
        //        final List<AbstractSubjectAltNameFieldValue> x400Addresses = pkiSubjectAltNameStringValuesFrom(subjectAltName.getX400Address());
        //        if (!x400Addresses.isEmpty()) {
        //            for(AbstractSubjectAltNameFieldValue absSANValue : x400Addresses) {
        //                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        //                subjectAltNameField.setType(SubjectAltNameFieldType.X400_ADDRESS);
        //                subjectAltNameField.setValue(absSANValue);
        //                subjectAltNameFieldList.add(subjectAltNameField);
        //            }
        //        }
        final List<AbstractSubjectAltNameFieldValue> ediPartyNames = pkiEdiPartyFrom(subjectAltName.getEdiPartyName());
        if (!ediPartyNames.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : ediPartyNames) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }
        final List<AbstractSubjectAltNameFieldValue> otherNames = pkiOtherNameFrom(subjectAltName.getOtherName());
        if (!otherNames.isEmpty()) {
            for (final AbstractSubjectAltNameFieldValue absSANValue : otherNames) {
                final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
                subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
                subjectAltNameField.setValue(absSANValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }

        ret.setSubjectAltNameFields(subjectAltNameFieldList);
        return ret;
    }

    /**
     * @param Algorithm
     * @return
     */
    public static CredentialManagerAlgorithm credMAlgorithmFrom(final Algorithm algorithm) {
        final CredentialManagerAlgorithm ret = new CredentialManagerAlgorithm();

        if (algorithm == null) {
            return null;
        }
        ret.setId(algorithm.getId());
        ret.setOid(algorithm.getOid());
        ret.setKeySize(algorithm.getKeySize());
        ret.setName(algorithm.getName());
        ret.setSupported(algorithm.isSupported());
        ret.setType(credMAlgorithmTypeFrom(algorithm.getType()));

        return ret;
    }

    public static CredentialManagerAlgorithmType credMAlgorithmTypeFrom(final AlgorithmType type) {
        return CredentialManagerAlgorithmType.fromValue(type.toString());
    }

    /**
     * @param Algorithm
     * @return
     */
    public static Algorithm pkiAlgorithmFrom(final CredentialManagerAlgorithm algorithm) {
        final Algorithm ret = new Algorithm();

        if (algorithm == null) {
            return null;
        }

        ret.setId(algorithm.getId());
        ret.setOid(algorithm.getOid());
        ret.setKeySize(algorithm.getKeySize());
        ret.setName(algorithm.getName());
        ret.setSupported(algorithm.isSupported());
        ret.setType(pkiAlgorithmTypeFrom(algorithm.getType()));

        return ret;
    }

    public static AlgorithmType pkiAlgorithmTypeFrom(final CredentialManagerAlgorithmType type) {
        return AlgorithmType.fromValue(type.toString());
    }

    public static List<AbstractSubjectAltNameFieldValue> pkiEdiPartyFrom(final List<CredentialManagerEdiPartyName> listEdiPartyName) {
        final List<AbstractSubjectAltNameFieldValue> pkiEdiPartyNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();

        for (final CredentialManagerEdiPartyName credmEdiPartyName : listEdiPartyName) {
            final EdiPartyName pkiEdiPartyName = new EdiPartyName();

            pkiEdiPartyName.setNameAssigner(credmEdiPartyName.getNameAssigner());
            pkiEdiPartyName.setPartyName(credmEdiPartyName.getPartyName());

            pkiEdiPartyNameList.add(pkiEdiPartyName);
        }
        return pkiEdiPartyNameList;
    }

    public static List<AbstractSubjectAltNameFieldValue> pkiOtherNameFrom(final List<CredentialManagerOtherName> listOtherName) {
        final List<AbstractSubjectAltNameFieldValue> pkiOtherNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        for (final CredentialManagerOtherName credmOtherName : listOtherName) {
            final OtherName pkiOtherName = new OtherName();
            pkiOtherName.setTypeId(credmOtherName.getTypeId());
            pkiOtherName.setValue(credmOtherName.getValue());

            pkiOtherNameList.add(pkiOtherName);
        }
        return pkiOtherNameList;
    }

    private static CredentialManagerSubject credMSubjectFrom(final Subject profileSubject) {
        CredentialManagerSubject subject = null;
        if (profileSubject != null && profileSubject.getSubjectFields() != null) {
            subject = new CredentialManagerSubject();

            for (final SubjectField value : profileSubject.getSubjectFields()) {
                if (value.getType() == SubjectFieldType.COMMON_NAME) {
                    subject.setCommonName(value.getValue());
                } else if (value.getType() == SubjectFieldType.COUNTRY_NAME) {
                    subject.setCountryName(value.getValue());
                } else if (value.getType() == SubjectFieldType.DN_QUALIFIER) {
                    subject.setDnQualifier(value.getValue());
                    //                    } else if (value.getKey() == SubjectFieldType.FULL_DN) {
                    //                        subject.put(CredentialManagerSubjectFieldType.FULL_DN, value.getValue());
                } else if (value.getType() == SubjectFieldType.GIVEN_NAME) {
                    subject.setGivenName(value.getValue());
                } else if (value.getType() == SubjectFieldType.LOCALITY_NAME) {
                    subject.setLocalityName(value.getValue());
                } else if (value.getType() == SubjectFieldType.ORGANIZATION) {
                    subject.setOrganizationName(value.getValue());
                } else if (value.getType() == SubjectFieldType.ORGANIZATION_UNIT) {
                    subject.setOrganizationalUnitName(value.getValue());
                } else if (value.getType() == SubjectFieldType.SERIAL_NUMBER) {
                    subject.setSerialNumber(value.getValue());
                } else if (value.getType() == SubjectFieldType.STATE) {
                    subject.setStateOrProvinceName(value.getValue());
                } else if (value.getType() == SubjectFieldType.STREET_ADDRESS) {
                    subject.setStreetAddress(value.getValue());
                } else if (value.getType() == SubjectFieldType.SURNAME) {
                    subject.setSurName(value.getValue());
                } else if (value.getType() == SubjectFieldType.TITLE) {
                    subject.setTitle(value.getValue());
                }
            }
        }
        return subject;
    }

    public static Subject pkiSubjectFrom(final CredentialManagerSubject s) {
        final Subject ret = new Subject();

        if (s == null) {
            return null;
        }

        if (s.retrieveSubjectDN() != null) {
            final List<SubjectField> subjectFieldList = new ArrayList<SubjectField>();
            SubjectField subjectField = null;
            if (s.getCommonName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.COMMON_NAME);
                subjectField.setValue(s.getCommonName());
                subjectFieldList.add(subjectField);
            }
            if (s.getCountryName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.COUNTRY_NAME);
                subjectField.setValue(s.getCountryName());
                subjectFieldList.add(subjectField);
            }
            if (s.getDnQualifier() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.DN_QUALIFIER);
                subjectField.setValue(s.getDnQualifier());
                subjectFieldList.add(subjectField);
            }
            if (s.getGivenName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.GIVEN_NAME);
                subjectField.setValue(s.getGivenName());
                subjectFieldList.add(subjectField);
            }
            if (s.getLocalityName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.LOCALITY_NAME);
                subjectField.setValue(s.getLocalityName());
                subjectFieldList.add(subjectField);
            }
            if (s.getOrganizationalUnitName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.ORGANIZATION_UNIT);
                subjectField.setValue(s.getOrganizationalUnitName());
                subjectFieldList.add(subjectField);
            }
            if (s.getOrganizationName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.ORGANIZATION);
                subjectField.setValue(s.getOrganizationName());
                subjectFieldList.add(subjectField);
            }
            if (s.getSerialNumber() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.SERIAL_NUMBER);
                subjectField.setValue(s.getSerialNumber());
                subjectFieldList.add(subjectField);
            }
            if (s.getStateOrProvinceName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.STATE);
                subjectField.setValue(s.getStateOrProvinceName());
                subjectFieldList.add(subjectField);
            }
            if (s.getSurName() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.SURNAME);
                subjectField.setValue(s.getSurName());
                subjectFieldList.add(subjectField);
            }
            if (s.getStreetAddress() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.STREET_ADDRESS);
                subjectField.setValue(s.getStreetAddress());
                subjectFieldList.add(subjectField);
            }
            if (s.getTitle() != null) {
                subjectField = new SubjectField();
                subjectField.setType(SubjectFieldType.TITLE);
                subjectField.setValue(s.getTitle());
                subjectFieldList.add(subjectField);
            }
            ret.setSubjectFields(subjectFieldList);
        }

        return ret;
    }

    /*
     * Certificate Extension Mapper
     */
    public static CredentialManagerCertificateExtensions credMExtensionFrom(final CertificateExtensions certificateExtensions) {
        final CredentialManagerCertificateExtensions ret = new CredentialManagerCertificateExtensions();

        if (certificateExtensions == null) {
            return null;
        }

        for (final CertificateExtension entry : certificateExtensions.getCertificateExtensions()) {
            if (entry.getClass() == AuthorityInformationAccess.class) {
                ret.setAuthorityInformationAccess(credMAuthInformationAccessFrom((AuthorityInformationAccess) entry));
            } else if (entry.getClass() == AuthorityKeyIdentifier.class) {
                ret.setAuthorityKeyIdentifier(credMAuthKeyIdentifierFrom((AuthorityKeyIdentifier) entry));
            } else if (entry.getClass() == BasicConstraints.class) {
                ret.setBasicConstraints(credMBasicConstraintsFrom((BasicConstraints) entry));
            } else if (entry.getClass() == CRLDistributionPoints.class) {
                ret.setCrlDistributionPoints(credMCRLDistributionPointsFrom((CRLDistributionPoints) entry));
            } else if (entry.getClass() == ExtendedKeyUsage.class) {
                ret.setExtendedKeyUsage(credMExtendedKeyUsageFrom((ExtendedKeyUsage) entry));
            } else if (entry.getClass() == KeyUsage.class) {
                ret.setKeyUsage(credMKeyUsageFrom((KeyUsage) entry));
                // TODO: DespicableUs bisognerebbe aggiunger i flag del subjectAltName
                //            } else if (entry.getKey() == CertificateExtensionType.SUBJECT_ALT_NAME) {
                //                key = CredentialManagerCertificateExtensionType.SUBJECT_ALT_NAME;
                //                final CredentialManagerSubjectAltName certExt = credMSubjectAltNameFrom((SubjectAltName) entry.getValue());
                //                ret.put(key, certExt);
            } else if (entry.getClass() == SubjectKeyIdentifier.class) {
                ret.setSubjectKeyIdentifier(credMSubjectKeyIdentifierFrom((SubjectKeyIdentifier) entry));
            }
        }

        return ret;
    }

    /*
     * Certificate Extension Mapper
     */
    public static CredentialManagerCertificateExtensions credMExtensionFrom(final CertificateExtensions certificateProfileCertificateExtensions,
                                                                            final CertificateExtensions entityProfileCertificateExtensions) {
        final CredentialManagerCertificateExtensions ret = new CredentialManagerCertificateExtensions();

        if (certificateProfileCertificateExtensions != null && certificateProfileCertificateExtensions.getCertificateExtensions() != null) {

            for (final CertificateExtension entry : certificateProfileCertificateExtensions.getCertificateExtensions()) {
                if (entry.getClass() == AuthorityInformationAccess.class) {
                    ret.setAuthorityInformationAccess(credMAuthInformationAccessFrom((AuthorityInformationAccess) entry));
                } else if (entry.getClass() == AuthorityKeyIdentifier.class) {
                    ret.setAuthorityKeyIdentifier(credMAuthKeyIdentifierFrom((AuthorityKeyIdentifier) entry));
                } else if (entry.getClass() == BasicConstraints.class) {
                    ret.setBasicConstraints(credMBasicConstraintsFrom((BasicConstraints) entry));
                } else if (entry.getClass() == CRLDistributionPoints.class) {
                    ret.setCrlDistributionPoints(credMCRLDistributionPointsFrom((CRLDistributionPoints) entry));
                } else if (entry.getClass() == ExtendedKeyUsage.class) {
                    ret.setExtendedKeyUsage(credMExtendedKeyUsageFrom((ExtendedKeyUsage) entry));
                } else if (entry.getClass() == KeyUsage.class) {
                    ret.setKeyUsage(credMKeyUsageFrom((KeyUsage) entry));
                    // TODO: DespicableUs bisognerebbe aggiunger i flag del subjectAltName
                    //            } else if (entry.getKey() == CertificateExtensionType.SUBJECT_ALT_NAME) {
                    //                key = CredentialManagerCertificateExtensionType.SUBJECT_ALT_NAME;
                    //                final CredentialManagerSubjectAltName certExt = credMSubjectAltNameFrom((SubjectAltName) entry.getValue());
                    //                ret.put(key, certExt);
                } else if (entry.getClass() == SubjectKeyIdentifier.class) {
                    ret.setSubjectKeyIdentifier(credMSubjectKeyIdentifierFrom((SubjectKeyIdentifier) entry));
                }
            }
        }

        if (entityProfileCertificateExtensions != null && entityProfileCertificateExtensions.getCertificateExtensions() != null) {
            for (final CertificateExtension entry : entityProfileCertificateExtensions.getCertificateExtensions()) {
                if (entry.getClass() == AuthorityInformationAccess.class) {
                    ret.setAuthorityInformationAccess(credMAuthInformationAccessFrom((AuthorityInformationAccess) entry));
                } else if (entry.getClass() == AuthorityKeyIdentifier.class) {
                    ret.setAuthorityKeyIdentifier(credMAuthKeyIdentifierFrom((AuthorityKeyIdentifier) entry));
                } else if (entry.getClass() == BasicConstraints.class) {
                    ret.setBasicConstraints(credMBasicConstraintsFrom((BasicConstraints) entry));
                } else if (entry.getClass() == CRLDistributionPoints.class) {
                    ret.setCrlDistributionPoints(credMCRLDistributionPointsFrom((CRLDistributionPoints) entry));
                } else if (entry.getClass() == ExtendedKeyUsage.class) {
                    ret.setExtendedKeyUsage(credMExtendedKeyUsageFrom((ExtendedKeyUsage) entry));
                } else if (entry.getClass() == KeyUsage.class) {
                    ret.setKeyUsage(credMKeyUsageFrom((KeyUsage) entry));
                    // TODO: DespicableUs bisognerebbe aggiunger i flag del subjectAltName
                    //            } else if (entry.getKey() == CertificateExtensionType.SUBJECT_ALT_NAME) {
                    //                key = CredentialManagerCertificateExtensionType.SUBJECT_ALT_NAME;
                    //                final CredentialManagerSubjectAltName certExt = credMSubjectAltNameFrom((SubjectAltName) entry.getValue());
                    //                ret.put(key, certExt);
                } else if (entry.getClass() == SubjectKeyIdentifier.class) {
                    ret.setSubjectKeyIdentifier(credMSubjectKeyIdentifierFrom((SubjectKeyIdentifier) entry));
                }
            }
        }

        return ret;
    }

    private static CredentialManagerSubjectKeyIdentifier credMSubjectKeyIdentifierFrom(final SubjectKeyIdentifier subjectKeyIdentifier) {
        final CredentialManagerSubjectKeyIdentifier credMSubjectKeyIdentifier = new CredentialManagerSubjectKeyIdentifier();

        if (subjectKeyIdentifier == null) {
            return null;
        }

        credMSubjectKeyIdentifier.setCritical(subjectKeyIdentifier.isCritical());
        credMSubjectKeyIdentifier.setKeyIdentifierAlgorithm(subjectKeyIdentifier.getKeyIdentifier().getAlgorithm().getName());

        return credMSubjectKeyIdentifier;
    }

    /**
     * @param keyUsage
     * @return
     */
    private static CredentialManagerKeyUsage credMKeyUsageFrom(final KeyUsage keyUsage) {
        final CredentialManagerKeyUsage credMKeyUsage = new CredentialManagerKeyUsage();

        if (keyUsage == null) {
            return null;
        }

        credMKeyUsage.setKeyUsageType(credMKeyUsageTypeFrom(keyUsage.getSupportedKeyUsageTypes()));

        return credMKeyUsage;
    }

    /**
     * @param keyUsageType
     * @return
     */
    private static List<CredentialManagerKeyUsageType> credMKeyUsageTypeFrom(final List<KeyUsageType> keyUsageTypeList) {
        final List<CredentialManagerKeyUsageType> credMKeyUsageTypeList = new ArrayList<CredentialManagerKeyUsageType>();
        for (final KeyUsageType keyUsageType : keyUsageTypeList) {
            credMKeyUsageTypeList.add(CredentialManagerKeyUsageType.fromValue(keyUsageType.getValue()));
        }
        return credMKeyUsageTypeList;
    }

    /**
     * @param extendedKeyUsage
     * @return
     */
    private static CredentialManagerExtendedKeyUsage credMExtendedKeyUsageFrom(final ExtendedKeyUsage extendedKeyUsage) {
        final CredentialManagerExtendedKeyUsage credMExtendedKeyUsage = new CredentialManagerExtendedKeyUsage();

        if (extendedKeyUsage == null) {
            return null;
        }

        credMExtendedKeyUsage.setCritical(extendedKeyUsage.isCritical());
        credMExtendedKeyUsage.setKeyPurposeId(credMExtendedKeyUsageFrom(extendedKeyUsage.getSupportedKeyPurposeIds()));

        return credMExtendedKeyUsage;
    }

    /**
     * @param keyPurposeId
     * @return
     */
    private static List<CredentialManagerKeyPurposeId> credMExtendedKeyUsageFrom(final List<KeyPurposeId> keyPurposeIdList) {
        final List<CredentialManagerKeyPurposeId> credMKeyPurposeIdList = new ArrayList<CredentialManagerKeyPurposeId>();
        for (final KeyPurposeId keyPurposeId : keyPurposeIdList) {
            credMKeyPurposeIdList.add(CredentialManagerKeyPurposeId.fromValue(keyPurposeId.getValue()));
        }
        return credMKeyPurposeIdList;
    }

    /**
     * @param entry
     * @return
     */
    private static CredentialManagerCRLDistributionPoints credMCRLDistributionPointsFrom(final CRLDistributionPoints entry) {
        final CredentialManagerCRLDistributionPoints credMCrlDistributionPoints = new CredentialManagerCRLDistributionPoints();
        if (entry == null) {
            return null;
        }
        final List<CredentialManagerCRLDistributionPoint> cRLDistributionPointList = new ArrayList<CredentialManagerCRLDistributionPoint>();
        for (final DistributionPoint pkiCRLDP : entry.getDistributionPoints()) {
            final CredentialManagerCRLDistributionPoint crlDP = credMCRLDistributionPointFrom(pkiCRLDP);
            cRLDistributionPointList.add(crlDP);
        }
        credMCrlDistributionPoints.setCritical(entry.isCritical());
        credMCrlDistributionPoints.setCRLDistributionPoints(cRLDistributionPointList);

        return credMCrlDistributionPoints;
    }

    /**
     * @param pkiCRLDP
     * @return
     */
    private static CredentialManagerCRLDistributionPoint credMCRLDistributionPointFrom(final DistributionPoint pkiCRLDP) {
        final CredentialManagerCRLDistributionPoint crlDP = new CredentialManagerCRLDistributionPoint();
        crlDP.setCRLIssuer(pkiCRLDP.getCRLIssuer());
        crlDP.setDistributionPointName(credMDistributionPointFrom(pkiCRLDP.getDistributionPointName()));
        crlDP.setReasonFlag(credMReasonFlagFrom(pkiCRLDP.getReasonFlag()));
        return crlDP;
    }

    /**
     * @param reasonFlag
     * @return
     */
    private static CredentialManagerReasonFlag credMReasonFlagFrom(final ReasonFlag reasonFlag) {
        if (reasonFlag != null) {
            return CredentialManagerReasonFlag.fromValue(reasonFlag.getValue());
        } else {
            return null;
        }
    }

    /**
     * @param distributionPointName
     * @return
     */
    private static CredentialManagerDistributionPointName credMDistributionPointFrom(final DistributionPointName distributionPointName) {
        final CredentialManagerDistributionPointName credmDistributionPointName = new CredentialManagerDistributionPointName();

        if (distributionPointName == null) {
            return null;
        }

        credmDistributionPointName.setFullName(distributionPointName.getFullName());
        credmDistributionPointName.setNameRelativeToCRLIssuer(distributionPointName.getNameRelativeToCRLIssuer());

        return credmDistributionPointName;
    }

    /**
     * @param basicConstraints
     * @return
     */
    private static CredentialManagerBasicConstraints credMBasicConstraintsFrom(final BasicConstraints basicConstraints) {
        final CredentialManagerBasicConstraints credMBasicConstraints = new CredentialManagerBasicConstraints();

        if (basicConstraints == null) {
            return null;
        }

        credMBasicConstraints.setCA(basicConstraints.isCA());
        credMBasicConstraints.setCritical(basicConstraints.isCritical());
        if (basicConstraints.getPathLenConstraint() != null) {
            credMBasicConstraints.setPathLenConstraint(basicConstraints.getPathLenConstraint());
        }
        return credMBasicConstraints;
    }

    /**
     * @param authorityKeyIdentifier
     * @return
     */
    private static CredentialManagerAuthorityKeyIdentifier credMAuthKeyIdentifierFrom(final AuthorityKeyIdentifier authorityKeyIdentifier) {
        final CredentialManagerAuthorityKeyIdentifier credMAuthorityKeyIdentifier = new CredentialManagerAuthorityKeyIdentifier();

        if (authorityKeyIdentifier == null) {
            return null;
        }
        if (authorityKeyIdentifier.getType().equals(AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER)) {
            credMAuthorityKeyIdentifier.setByAuthorityCertIssuerAndSerialNumber(true);
        } else if (authorityKeyIdentifier.getType().equals(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER)) {
            credMAuthorityKeyIdentifier.setByKeyIdentifier(true);
        }

        credMAuthorityKeyIdentifier.setCritical(authorityKeyIdentifier.isCritical());
        return credMAuthorityKeyIdentifier;
    }

    /**
     * @param accessDescription
     * @return
     */
    private static CredentialManagerAccessDescription credMAccessDescriptionFrom(final AccessDescription accessDescription) {
        final CredentialManagerAccessDescription credentialManagerAccessDescription = new CredentialManagerAccessDescription();

        if (accessDescription == null) {
            return null;
        }

        credentialManagerAccessDescription.setAccessLocation(accessDescription.getAccessLocation());
        credentialManagerAccessDescription.setAccessMethod(credMAccessMethodFrom(accessDescription.getAccessMethod()));

        return credentialManagerAccessDescription;
    }

    /**
     * @param authorityInformationAccess
     * @return
     */
    private static CredentialManagerAuthorityInformationAccess credMAuthInformationAccessFrom(final AuthorityInformationAccess authorityInformationAccess) {
        final CredentialManagerAuthorityInformationAccess credMAuthorityInformationAccess = new CredentialManagerAuthorityInformationAccess();

        if (authorityInformationAccess == null) {
            return null;
        }

        for (final AccessDescription pkiAccessDescription : authorityInformationAccess.getAccessDescriptions()) {
            final CredentialManagerAccessDescription accessDescription = credMAccessDescriptionFrom(pkiAccessDescription);
            credMAuthorityInformationAccess.getAccessDescription().add(accessDescription);

        }
        credMAuthorityInformationAccess.setCritical(authorityInformationAccess.isCritical());

        return credMAuthorityInformationAccess;
    }

    /**
     * @param accessMethod
     * @return
     */
    private static CredentialManagerAccessMethod credMAccessMethodFrom(final AccessMethod accessMethod) {
        if (accessMethod == null) {
            return null;
        }

        return CredentialManagerAccessMethod.fromValue(accessMethod.toString());
    }

    /**
     * @param csr
     * @return
     * @throws CertificateEncodingException
     */
    public static PKCS10CertificationRequestHolder pkiPKCS10CertRequestFrom(final CredentialManagerPKCS10CertRequest csr)
            throws CredentialManagerCertificateEncodingException {
        try {
            final PKCS10CertificationRequest pKCS10CertificationRequest = csr.getRequest();

            final PKCS10CertificationRequestHolder pkiCertRequest = new PKCS10CertificationRequestHolder(pKCS10CertificationRequest);
            return pkiCertRequest;

        } catch (final IOException ex) {
            throw new CredentialManagerCertificateEncodingException(ex.getMessage());
        }
    }

    /**
     * @param csr
     * @return
     * @throws CertificateEncodingException
     */
    public static CertificateRequest pkiCSRFrom(final CredentialManagerPKCS10CertRequest csr) throws CredentialManagerCertificateEncodingException {
        final PKCS10CertificationRequestHolder pkiCertRequest = pkiPKCS10CertRequestFrom(csr);
        final CertificateRequest pkiCSR = new CertificateRequest();
        pkiCSR.setCertificateRequestHolder(pkiCertRequest);
        return pkiCSR;
    }

    /**
     * @param pkiCertificate
     * @return
     * @throws CertificateEncodingException
     */
    public static CredentialManagerX509Certificate credMCertificateFrom(final Certificate pkiCertificate)
            throws CredentialManagerCertificateEncodingException {
        try {

            final CredentialManagerX509Certificate certificate = new CredentialManagerX509Certificate(pkiCertificate.getX509Certificate());
            return certificate;

        } catch (final CertificateEncodingException ex) {
            throw new CredentialManagerCertificateEncodingException(ex.getMessage());
        }
    }

    /**
     * @param crlHolder
     * @return
     * @throws CredentialManagerCertificateEncodingException
     */
    public static CredentialManagerX509CRL credmX509CRLfrom(final X509CRLHolder crlHolder) throws CredentialManagerCertificateEncodingException {
        CredentialManagerX509CRL crl = null;
        try {
            crl = new CredentialManagerX509CRL(crlHolder.retrieveCRL());
        } catch (final CRLEncodingException e) {
            throw new CredentialManagerCertificateEncodingException(e.getMessage());
        }
        return crl;
    }

    public static CredentialManagerX509CRL credMCrlFrom(final ExternalCRLInfo pkiCrl) throws CredentialManagerCRLEncodingException {
        try {
            final CredentialManagerX509CRL crl = new CredentialManagerX509CRL(pkiCrl.getX509CRL().getCrlBytes());
            return crl;
        } catch (final CRLEncodingException e) {
            throw new CredentialManagerCRLEncodingException(e.getMessage());
        }
    }

    public static EntityType pkiEntityTypeFrom(final CredentialManagerEntityType eType) {
        return EntityType.fromValue(eType.toString());
    }
}
