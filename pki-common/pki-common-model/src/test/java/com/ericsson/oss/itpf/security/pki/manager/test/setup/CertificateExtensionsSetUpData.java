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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

/**
 * This class acts as builder for {@link CertificateExtensionsSetUpData}
 */
public class CertificateExtensionsSetUpData {
    /**
     * Method that returns valid CertificateExtensions
     * 
     * @return CertificateExtensions
     * @throws Exception
     */
    public CertificateExtensions buildEqualCertificateExtensions() {
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        certificateExtensionList.add((CertificateExtension) new BasicConstraintsTest().createInstance());
        certificateExtensionList.add((CertificateExtension) new AuthorityInformationAccessTest().createInstance());
        certificateExtensionList.add((CertificateExtension) new AuthorityKeyIdentifierTest().createInstance());
        certificateExtensionList.add((CertificateExtension) new SubjectKeyIdentifierTest().createInstance());
        certificateExtensionList.add(buildSubjectAltNameForEqual(true));
        certificateExtensionList.add((CertificateExtension) new KeyUsageTest().createInstance());
        certificateExtensionList.add((CertificateExtension) new ExtendedKeyUsageTest().createInstance());
        certificateExtensionList.add(buildCRLDistributionPointForEqual(true));
        return certificateExtensions;
    }

    /**
     * Method that returns different valid CertificateExtensions
     * 
     * @return CertificateExtensions
     */
    public CertificateExtensions buildNotEqualCertificateExtensions() {
        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        certificateExtensionList.add((CertificateExtension) new BasicConstraintsTest().createNotEqualInstance());
        certificateExtensionList.add((CertificateExtension) new AuthorityInformationAccessTest().createNotEqualInstance());
        certificateExtensionList.add((CertificateExtension) new AuthorityKeyIdentifierTest().createNotEqualInstance());
        certificateExtensionList.add((CertificateExtension) new SubjectKeyIdentifierTest().createNotEqualInstance());
        certificateExtensionList.add(buildSubjectAltNameForNotEqual(false));
        certificateExtensionList.add((CertificateExtension) new KeyUsageTest().createNotEqualInstance());
        certificateExtensionList.add((CertificateExtension) new ExtendedKeyUsageTest().createNotEqualInstance());
        certificateExtensionList.add(buildCRLDistributionPointForNotEqual(false));
        return certificateExtensions;
    }

    /**
     * Method that returns valid CRLDistributionPoints
     * 
     * @return CRLDistributionPoints
     */
    public CRLDistributionPoints buildCRLDistributionPointForEqual(final boolean critical) {
        final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
        crlDistributionPoints.setCritical(critical);
        final List<DistributionPoint> crDistributionPointList = new ArrayList<DistributionPoint>();
        crDistributionPointList.add((DistributionPoint) new CRLDistributionPointTest().createInstance());
        crlDistributionPoints.setDistributionPoints(crDistributionPointList);
        return crlDistributionPoints;
    }

    /**
     * Method that returns different valid CRLDistributionPoints
     * 
     * @return CRLDistributionPoints
     */
    public CRLDistributionPoints buildCRLDistributionPointForNotEqual(final boolean critical) {
        final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
        crlDistributionPoints.setCritical(critical);
        final List<DistributionPoint> crDistributionPointList = new ArrayList<DistributionPoint>();
        crDistributionPointList.add((DistributionPoint) new CRLDistributionPointTest().createNotEqualInstance());
        crlDistributionPoints.setDistributionPoints(crDistributionPointList);
        return crlDistributionPoints;
    }

    /**
     * Method that returns valid SubjectAltName
     * 
     * @return SubjectAltName
     */
    public SubjectAltName buildSubjectAltNameForEqual(final boolean critical) {
        final SubjectAltName subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        final OtherName otherName = new OtherName();
        otherName.setTypeId("type_other_name");
        otherName.setValue("value_other_name");

        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameField.setValue(otherName);
        subjectAltNameFields.add(subjectAltNameField);

        subjectAltName.setCritical(critical);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    /**
     * Method that returns different valid SubjectAltName
     * 
     * @return SubjectAltName
     */
    public SubjectAltName buildSubjectAltNameForNotEqual(final boolean critical) {
        final SubjectAltName subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        final EdiPartyName ediPartyName = new EdiPartyName();
        ediPartyName.setNameAssigner("edi_party_name_assigner");
        ediPartyName.setPartyName("edi_party_name");

        subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameField.setValue(ediPartyName);
        subjectAltNameFields.add(subjectAltNameField);

        subjectAltName.setCritical(critical);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }
}
