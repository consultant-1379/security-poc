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
import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlAbstractSubjectAltNameValueType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlAccessDescription;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCACRL;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCRLGenerationInfo;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCrlExtensions;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlDistributionPointName;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEdiPartyName;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlIssuingDistributionPoint;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlOtherName;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlReasonFlag;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectAltNameString;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectAltNameValue;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectFieldType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectMapModeller;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessDescription;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityInformationAccess;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifierType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.IssuingDistributionPoint;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public final class PkiCAEntityMapper {

    private PkiCAEntityMapper() {
    } //Only static methods

    public static CAEntity ConvertEntityFrom(final XmlCAEntity xmlCAEntity) throws PkiEntityMapperException {

        final CAEntity pkiCAEntity = new CAEntity();
        final CertificateAuthority certAuth = new CertificateAuthority();

        final Algorithm pkiAlgorithm = new Algorithm();

        if (xmlCAEntity == null) {
            throw new PkiEntityMapperException("Input parameter is NULL");
        }

        /**
         * set PublishCertificatetoTDPS
         */
        if (xmlCAEntity.isPublishCertificatetoTDPS() != null) {
            pkiCAEntity.setPublishCertificatetoTDPS(xmlCAEntity.isPublishCertificatetoTDPS());
        }

        /**
         * set RootCA
         */

        certAuth.setRootCA(xmlCAEntity.isRootCA());

        /**
         * setEntityProfileName
         */
        if (pkiCAEntity.getEntityProfile() == null) {
            final EntityProfile entityprofile = new EntityProfile();
            pkiCAEntity.setEntityProfile(entityprofile);
        }
        pkiCAEntity.getEntityProfile().setName(xmlCAEntity.getEntityProfileName());

        /**
         * set CACRL:
         * 
         * @XmlElement(name = "PublishCRLToCDPS") protected boolean publishCRLToCDPS;
         * @XmlElement(name = "CRLGenerationInfo") protected List<XmlCRLGenerationInfo> crlGenerationInfo;
         * */
        /**
         * set CRL Generation Info:
         * 
         * @XmlElement(name = "Version", required = true) protected String version;
         * @XmlElement(name = "SignatureAlgorithm", required = true) protected XmlAlgorithm signatureAlgorithm;
         * @XmlElement(name = "ValidityPeriod", required = true) protected Duration validityPeriod;
         * @XmlElement(name = "SkewCrlTime", required = true) protected Duration skewCrlTime;
         * @XmlElement(name = "OverlapPeriod", required = true) protected Duration overlapPeriod;
         * @XmlElement(name = "CrlExtensions") protected XmlCrlExtensions crlExtensions;
         **/
        if (xmlCAEntity.getCACRL() != null) {

            final XmlCACRL xmlCACRL = xmlCAEntity.getCACRL();

            certAuth.setPublishToCDPS(xmlCACRL.isPublishCRLToCDPS());

            if (xmlCACRL.getCRLGenerationInfo() != null) {

                final List<XmlCRLGenerationInfo> xmlCrlGenerationInfoList = xmlCACRL.getCRLGenerationInfo();
                final List<CrlGenerationInfo> pkiCrlGenerationInfoList = new ArrayList<CrlGenerationInfo>();

                for (XmlCRLGenerationInfo xmlCrlGenerationInfo : xmlCrlGenerationInfoList) {
                    final CrlGenerationInfo pkiCrlGenerationInfo = new CrlGenerationInfo();

                    /*
                     * CRL Version : To speak about string or enum in file.xsd with Marco
                     */
                    if (xmlCrlGenerationInfo.getVersion() != null) {
                        if (xmlCrlGenerationInfo.getVersion().equalsIgnoreCase("v2")) {
                            pkiCrlGenerationInfo.setVersion(CRLVersion.V2);
                        }
                    }
                    /*
                     * CRL Signature Algorithm
                     */
                    if (xmlCrlGenerationInfo.getSignatureAlgorithm() != null) {
                        final Algorithm pkiCrlAlgorithm = new Algorithm();

                        pkiCrlAlgorithm.setKeySize(xmlCrlGenerationInfo.getSignatureAlgorithm().getKeySize().intValue());
                        pkiCrlAlgorithm.setName(xmlCrlGenerationInfo.getSignatureAlgorithm().getName());

                        pkiCrlGenerationInfo.setSignatureAlgorithm(pkiCrlAlgorithm);
                    }
                    /*
                     * CRL Validity Period
                     */
                    if (xmlCrlGenerationInfo.getValidityPeriod() != null) {
                        pkiCrlGenerationInfo.setValidityPeriod(xmlCrlGenerationInfo.getValidityPeriod());
                    }
                    /*
                     * CRL SKEW Time
                     */
                    if (xmlCrlGenerationInfo.getSkewCrlTime() != null) {
                        pkiCrlGenerationInfo.setSkewCrlTime(xmlCrlGenerationInfo.getSkewCrlTime());
                    }
                    /*
                     * CRL Overlap Period
                     */
                    if (xmlCrlGenerationInfo.getOverlapPeriod() != null) {
                        pkiCrlGenerationInfo.setOverlapPeriod(xmlCrlGenerationInfo.getOverlapPeriod());
                    }
                    /*
                     * CRL Extensions
                     */
                    if (xmlCrlGenerationInfo.getCrlExtensions() != null) {
                        final XmlCrlExtensions xmlCrlExtensions = xmlCrlGenerationInfo.getCrlExtensions();
                        final CrlExtensions pkiCrlExtensions = new CrlExtensions();

                        /*
                         * CRL Number
                         */
                        if (xmlCrlExtensions.getCRLNumber() != null) {
                            final CRLNumber pkiCRLNumber = new CRLNumber();
                            pkiCRLNumber.setCritical(xmlCrlExtensions.getCRLNumber().isCritical());

                            pkiCrlExtensions.setCrlNumber(pkiCRLNumber);
                        }
                        /*
                         * Authority Information Access
                         */
                        if (xmlCrlExtensions.getAuthorityInformationAccess() != null) {
                            final AuthorityInformationAccess pkiAuthorityInformationAccess = new AuthorityInformationAccess();

                            pkiAuthorityInformationAccess.setCritical(xmlCrlExtensions.getAuthorityInformationAccess().isCritical());

                            if (xmlCrlExtensions.getAuthorityInformationAccess().getAccessDescription() != null) {
                                final List<XmlAccessDescription> xmlAccessDescriptionList = xmlCrlExtensions.getAuthorityInformationAccess().getAccessDescription();
                                final List<AccessDescription> pkiAccessDescriptionsList = new ArrayList<AccessDescription>();

                                for (XmlAccessDescription xmlAccessDescription : xmlAccessDescriptionList) {
                                    final AccessDescription pkiAccessDescription = new AccessDescription();

                                    if (xmlAccessDescription.getAccessMethod() != null) {
                                        pkiAccessDescription.setAccessMethod(AccessMethod.fromValue(xmlAccessDescription.getAccessMethod().value()));
                                    }
                                    if (xmlAccessDescription.getAccessLocation() != null) {
                                        pkiAccessDescription.setAccessLocation(xmlAccessDescription.getAccessLocation().getValue());
                                    }

                                    pkiAccessDescriptionsList.add(pkiAccessDescription);
                                }

                                pkiAuthorityInformationAccess.setAccessDescriptions(pkiAccessDescriptionsList);
                            }

                            pkiCrlExtensions.setAuthorityInformationAccess(pkiAuthorityInformationAccess);
                        }
                        /*
                         * Authority Key Identifier
                         */
                        if (xmlCrlExtensions.getAuthorityKeyIdentifier() != null) {
                            final AuthorityKeyIdentifier pkiAuthorityKeyIdentifier = new AuthorityKeyIdentifier();

                            pkiAuthorityKeyIdentifier.setCritical(xmlCrlExtensions.getAuthorityKeyIdentifier().isCritical());

                            if (xmlCrlExtensions.getAuthorityKeyIdentifier().isByKeyIdentifier() != null) {
                                if (xmlCrlExtensions.getAuthorityKeyIdentifier().isByKeyIdentifier()) {
                                    pkiAuthorityKeyIdentifier.setType(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);
                                }
                            }
                            if (xmlCrlExtensions.getAuthorityKeyIdentifier().isByAuthorityCertIssuerAndSerialNumber() != null) {
                                if (xmlCrlExtensions.getAuthorityKeyIdentifier().isByAuthorityCertIssuerAndSerialNumber()) {
                                    pkiAuthorityKeyIdentifier.setType(AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER);
                                }
                            }

                            pkiCrlExtensions.setAuthorityKeyIdentifier(pkiAuthorityKeyIdentifier);
                        }
                        /*
                         * Issuing Distribution Point : To speak about reason flag with Marco (we have only ONE and PKI has a LIST)
                         */
                        if (xmlCrlExtensions.getIssuingDistributionPoint() != null) {
                            final XmlIssuingDistributionPoint xmlIssuingDistributionPoint = xmlCrlExtensions.getIssuingDistributionPoint();
                            final IssuingDistributionPoint pkiIssuingDistributionPoint = new IssuingDistributionPoint();

                            pkiIssuingDistributionPoint.setCritical(xmlIssuingDistributionPoint.isCritical());
                            pkiIssuingDistributionPoint.setOnlyContainsAttributeCerts(xmlIssuingDistributionPoint.isOnlyContainsAttributeCerts());
                            // Currently in PKI System, this field is not supported, So PKI system will not expect
                            // this field from XML while creating CA Entity with CRLGenerationInfo.
                            // pkiIssuingDistributionPoint.setIndirectCRL(xmlIssuingDistributionPoint.isIndirectCRL());
                            pkiIssuingDistributionPoint.setOnlyContainsCACerts(xmlIssuingDistributionPoint.isOnlyContainsCACerts());
                            pkiIssuingDistributionPoint.setOnlyContainsUserCerts(xmlIssuingDistributionPoint.isOnlyContainsUserCerts());

                            if (xmlIssuingDistributionPoint.getDistributionPoint() != null) {
                                final XmlDistributionPointName xmlDistributionPointName = xmlIssuingDistributionPoint.getDistributionPoint();
                                final DistributionPointName pkiDistributionPointName = new DistributionPointName();

                                pkiDistributionPointName.setFullName(xmlDistributionPointName.getFullName());
                                pkiDistributionPointName.setNameRelativeToCRLIssuer(xmlDistributionPointName.getNameRelativeToCRLIssuer());

                                pkiIssuingDistributionPoint.setDistributionPoint(pkiDistributionPointName);
                            }

                            if (xmlIssuingDistributionPoint.getReasonFlag() != null) {
                                final List<XmlReasonFlag> xmlReasonFlags = xmlIssuingDistributionPoint.getReasonFlag();
                                final List<ReasonFlag> pkiReasonFlags = new ArrayList<ReasonFlag>();
                                for (XmlReasonFlag xmlReasonFlag : xmlReasonFlags) {
                                    pkiReasonFlags.add(ReasonFlag.fromId(xmlReasonFlag.ordinal()+1)); //ordinal starts from zero, ReasonFlag does not
                                }
                                pkiIssuingDistributionPoint.setOnlySomeReasons(pkiReasonFlags);
                            }

                            pkiCrlExtensions.setIssuingDistributionPoint(pkiIssuingDistributionPoint);
                        }

                        pkiCrlGenerationInfo.setCrlExtensions(pkiCrlExtensions);
                    }

                    pkiCrlGenerationInfoList.add(pkiCrlGenerationInfo);

                }
                certAuth.setCrlGenerationInfo(pkiCrlGenerationInfoList);
            }

        }
        /**
         * setKeyGenerationAlgorithm
         */

        if (xmlCAEntity.getKeyGenerationAlgorithm() != null) {
            pkiAlgorithm.setKeySize(xmlCAEntity.getKeyGenerationAlgorithm().getKeySize().intValue());
            pkiAlgorithm.setName(xmlCAEntity.getKeyGenerationAlgorithm().getName());

            pkiCAEntity.setKeyGenerationAlgorithm(pkiAlgorithm);
        }

        /**
         * setName
         */

        certAuth.setName(xmlCAEntity.getName());

        /**
         * setSubject
         */

        Subject subject = new Subject();

        if (xmlCAEntity.getSubject() != null) {
            final List<XmlSubjectMapModeller.XmlSubjectEntry> xmlsubjectenty = xmlCAEntity.getSubject().getSubjectDN().getSubjectEntry();
            final Subject pkiCASubject = new Subject();
            for (final XmlSubjectMapModeller.XmlSubjectEntry xmlsubjectentry : xmlsubjectenty) {
                final SubjectField subField = new SubjectField();
                subField.setType(convertSubjectFieldType(xmlsubjectentry.getType()));
                subField.setValue(xmlsubjectentry.getValue());
                pkiCASubject.getSubjectFields().add(subField);
            }
            //pkiCASubject.setSubjectDN(subjectMap);
            subject = pkiCASubject;
        }
        certAuth.setSubject(subject);

        /**
         * getSubjectAltNameValues
         */

        SubjectAltName subjectaltname = new SubjectAltName();

        if (xmlCAEntity.getSubjectAltNameValues() != null) {
            final SubjectAltName pkisubjectAltName = new SubjectAltName();

            final List<XmlSubjectAltNameValue> xmlsubjectAltNameValue = xmlCAEntity.getSubjectAltNameValues().getSubjectAltNameValue();

            final List<SubjectAltNameField> pkiSubjectAltNameFieldList = new ArrayList<SubjectAltNameField>();

            for (final XmlSubjectAltNameValue xmlsubjectaltnamevalue : xmlsubjectAltNameValue) {

                final SubjectAltNameField subANFTemp = new SubjectAltNameField();
                subANFTemp.setType(convertSubjectAltName(xmlsubjectaltnamevalue.getType()));

                final XmlAbstractSubjectAltNameValueType XmlAbstractAltNameType = xmlsubjectaltnamevalue.getValue();
                if (XmlAbstractAltNameType instanceof XmlSubjectAltNameString) {
                    final SubjectAltNameString y = new SubjectAltNameString();

                    if (((XmlSubjectAltNameString) XmlAbstractAltNameType).getStringValue() != null) {
                        y.setValue(((XmlSubjectAltNameString) XmlAbstractAltNameType).getStringValue());
                    }
                    subANFTemp.setValue(y);
                }

                if (XmlAbstractAltNameType instanceof XmlOtherName) {
                    final OtherName y = new OtherName();
                    y.setTypeId(((XmlOtherName) XmlAbstractAltNameType).getTypeId());
                    y.setValue(((XmlOtherName) XmlAbstractAltNameType).getValue());
                    subANFTemp.setValue(y);
                }

                if (XmlAbstractAltNameType instanceof XmlEdiPartyName) {
                    final EdiPartyName y = new EdiPartyName();
                    y.setNameAssigner(((XmlEdiPartyName) XmlAbstractAltNameType).getNameAssigner());
                    y.setPartyName(((XmlEdiPartyName) XmlAbstractAltNameType).getPartyName());
                    subANFTemp.setValue(y);
                }
                pkiSubjectAltNameFieldList.add(subANFTemp);

            }
            pkisubjectAltName.setSubjectAltNameFields(pkiSubjectAltNameFieldList);
            subjectaltname = pkisubjectAltName;
        }

        certAuth.setSubjectAltName(subjectaltname);
        pkiCAEntity.setCertificateAuthority(certAuth);
        return pkiCAEntity;
    }

    private static SubjectFieldType convertSubjectFieldType(final XmlSubjectFieldType xmlType) throws PkiEntityMapperException {

        switch (xmlType) {
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
            throw new PkiEntityMapperException("Unexpected XmlSubjectFieldType value to convert");

        }

    }

    private static SubjectAltNameFieldType convertSubjectAltName(final XmlSubjectAltNameFieldType xmlType) throws PkiEntityMapperException {

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
            throw new PkiEntityMapperException("Unexpected XmlSubjectAltNameFieldType value to convert");

        }

    }

}
