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

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPoint;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class CRLDistributionPointsBuilderTest extends BaseTest {

    @InjectMocks
    private CRLDistributionPointsBuilder crlDistributionPointsBuilder;

    CRLDistributionPoints crlDistribution = null;

    private static final boolean isCritical = true;

    /**
     * Test method for {@link CRLDistributionPoints} with reason code CA Compromise
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithCACompromise() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.CA_COMPROMISE);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.cACompromise));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code AA Compromise
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithAACOMPROMISE() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.AA_COMPROMISE);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.aACompromise));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code Affiliation Changed
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithAffiliationChanged() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.AFFILIATION_CHANGED);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.affiliationChanged));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code Certificate Hold
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithCertificateHold() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.CERTIFICATE_HOLD);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.certificateHold));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code CessationOfOperation
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithCessationOfOperation() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.CESSATION_OF_OPERATION);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.cessationOfOperation));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code KeyCompromise
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithKeyCompromise() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.KEY_COMPROMISE);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.keyCompromise));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code PrivilegeWithdrawn
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithPrivilegeWithPrivilegeWithdrawn() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.PRIVILEGE_WITHDRAWN);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.privilegeWithdrawn));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code PrivilegeWithdrawn
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithPrivilegeWithSuperseded() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.SUPERSEDED);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.superseded));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with reason code unused
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testCRLDistributionPointsByFullNameWithUnUsed() throws IOException {
        generateCRLDistributionPointByFullName(ReasonFlag.UNUSED);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByFullNames(crlDistribution, new ReasonFlags(ReasonFlags.unused));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with NameRelativeToCRLIssuer option
     * 
     * @throws IOException
     */
    @Ignore
    @Test
    public void testCRLDistributionPointsByNameRelativeToCRLIssuer() throws IOException {
        generateCRLDistributionPointByNameRealtiveToCRLIssuer(ReasonFlag.CA_COMPROMISE);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByNameRelativeToCRLIssuer(crlDistribution, new ReasonFlags(ReasonFlags.cACompromise));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    /**
     * Test method for {@link CRLDistributionPoints} with CRLIssuer option
     * 
     * @throws IOException
     */
    @Ignore
    @Test
    public void testCRLDistributionPointsByCRLIssuer() throws IOException {
        generateCRLDistributionPointByCRLIssuer(ReasonFlag.CA_COMPROMISE);

        final Extension cRLDistributionPointsActual = crlDistributionPointsBuilder.buildCRLDistributionPoints(crlDistribution);
        final DEROctetString cRLDistributionPointsExpected = getDistributionsPointByCRLIssuer(crlDistribution, new ReasonFlags(ReasonFlags.cACompromise));

        assertExtensionValue(cRLDistributionPointsExpected, cRLDistributionPointsActual);
        assertEquals(Extension.cRLDistributionPoints, cRLDistributionPointsActual.getExtnId());
    }

    private void generateCRLDistributionPointByFullName(final ReasonFlag reasonFlag) {
        crlDistribution = new CRLDistributionPoints();
        final List<DistributionPoint> distributionPoints = new ArrayList<DistributionPoint>();
        final DistributionPoint distributionPoint = new DistributionPoint();
        final DistributionPointName distributionPointName = new DistributionPointName();

        final List<String> fullName = new ArrayList<String>();
        fullName.add("ldap://ldap.example.com/cn=exampleCA,dc=example,dc=com?certificateRevocationList;binary");
        distributionPointName.setFullName(fullName);

        distributionPoint.setReasonFlag(reasonFlag);
        distributionPoint.setDistributionPointName(distributionPointName);
        distributionPoints.add(distributionPoint);
        crlDistribution.setCritical(isCritical);
        crlDistribution.setDistributionPoints(distributionPoints);
    }

    private void generateCRLDistributionPointByNameRealtiveToCRLIssuer(final ReasonFlag reasonFlag) {
        crlDistribution = new CRLDistributionPoints();
        final List<DistributionPoint> distributionPoints = new ArrayList<DistributionPoint>();
        final DistributionPoint distributionPoint = new DistributionPoint();
        final DistributionPointName distributionPointName = new DistributionPointName();

        final String nameRelativeToCRLIssuer = "CN=TestCA";
        distributionPointName.setNameRelativeToCRLIssuer(nameRelativeToCRLIssuer);

        distributionPoint.setReasonFlag(reasonFlag);
        distributionPoint.setDistributionPointName(distributionPointName);
        distributionPoints.add(distributionPoint);

        crlDistribution.setCritical(isCritical);
        crlDistribution.setDistributionPoints(distributionPoints);
    }

    private void generateCRLDistributionPointByCRLIssuer(final ReasonFlag reasonFlag) {
        final String cRLIssuer = "CN=TestCA";
        crlDistribution = new CRLDistributionPoints();
        final List<DistributionPoint> distributionPoints = new ArrayList<DistributionPoint>();
        final DistributionPoint distributionPoint = new DistributionPoint();

        distributionPoint.setCRLIssuer(cRLIssuer);
        distributionPoint.setReasonFlag(reasonFlag);

        distributionPoints.add(distributionPoint);

        crlDistribution.setCritical(isCritical);
        crlDistribution.setDistributionPoints(distributionPoints);
    }

    private DEROctetString getDistributionsPointByFullNames(final CRLDistributionPoints cRLDistributionPoints, final ReasonFlags reasonFlag) throws IOException {
        final List<GeneralName> cRLGeneralNameList = new ArrayList<GeneralName>();

        final List<DistributionPoint> distributionPoints = cRLDistributionPoints.getDistributionPoints();

        final List<org.bouncycastle.asn1.x509.DistributionPoint> distributionPointNames = new ArrayList<org.bouncycastle.asn1.x509.DistributionPoint>();

        for (final DistributionPoint distributionPoint : distributionPoints) {
            if (distributionPoint.getDistributionPointName() != null) {

                if (distributionPoint.getDistributionPointName().getFullName() != null && distributionPoint.getDistributionPointName().getFullName().size() > 0) {

                    final List<String> cRLUrls = distributionPoint.getDistributionPointName().getFullName();

                    for (final String cRlUrl : cRLUrls) {
                        cRLGeneralNameList.add(new GeneralName(GeneralName.uniformResourceIdentifier, cRlUrl));
                    }
                    final GeneralNames cRLGeneralNames = new GeneralNames(cRLGeneralNameList.toArray(new GeneralName[0]));
                    final org.bouncycastle.asn1.x509.DistributionPointName distributionPointName = new org.bouncycastle.asn1.x509.DistributionPointName(
                            org.bouncycastle.asn1.x509.DistributionPointName.FULL_NAME, cRLGeneralNames);

                    distributionPointNames.add(new org.bouncycastle.asn1.x509.DistributionPoint(distributionPointName, reasonFlag, null));
                }
            }
        }
        final CRLDistPoint cRLDistPoint = new CRLDistPoint(distributionPointNames.toArray(new org.bouncycastle.asn1.x509.DistributionPoint[0]));

        final DEROctetString cRLDistributionPointExtension = new DEROctetString(cRLDistPoint);

        return cRLDistributionPointExtension;
    }

    private DEROctetString getDistributionsPointByNameRelativeToCRLIssuer(final CRLDistributionPoints cRLDistributionPoints, final ReasonFlags reasonFlag) throws IOException {

        final List<GeneralName> cRLGeneralNameList = new ArrayList<GeneralName>();

        final List<DistributionPoint> distributionPoints = cRLDistributionPoints.getDistributionPoints();

        final List<org.bouncycastle.asn1.x509.DistributionPoint> distributionPointNames = new ArrayList<org.bouncycastle.asn1.x509.DistributionPoint>();

        for (final DistributionPoint distributionPoint : distributionPoints) {
            if (distributionPoint.getDistributionPointName() != null) {

                if (distributionPoint.getDistributionPointName().getNameRelativeToCRLIssuer() != null) {

                    cRLGeneralNameList.add(new GeneralName(new X500Name(distributionPoint.getDistributionPointName().getNameRelativeToCRLIssuer())));

                    final GeneralNames cRLGeneralNames = new GeneralNames(cRLGeneralNameList.toArray(new GeneralName[0]));

                    final org.bouncycastle.asn1.x509.DistributionPointName distributionPointName = new org.bouncycastle.asn1.x509.DistributionPointName(
                            org.bouncycastle.asn1.x509.DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER, cRLGeneralNames);

                    distributionPointNames.add(new org.bouncycastle.asn1.x509.DistributionPoint(distributionPointName, reasonFlag, null));
                }
            }
        }
        final CRLDistPoint cRLDistPoint = new CRLDistPoint(distributionPointNames.toArray(new org.bouncycastle.asn1.x509.DistributionPoint[0]));
        final DEROctetString cRLDistributionPointExtension = new DEROctetString(cRLDistPoint);

        return cRLDistributionPointExtension;
    }

    private DEROctetString getDistributionsPointByCRLIssuer(final CRLDistributionPoints cRLDistributionPoints, final ReasonFlags reasonFlag) throws IOException {

        final List<GeneralName> cRLGeneralNameList = new ArrayList<GeneralName>();

        final List<org.bouncycastle.asn1.x509.DistributionPoint> distributionPointNames = new ArrayList<org.bouncycastle.asn1.x509.DistributionPoint>();

        final List<DistributionPoint> distributionPoints = cRLDistributionPoints.getDistributionPoints();
        for (final DistributionPoint distributionPoint : distributionPoints) {
            if (distributionPoint.getCRLIssuer() != null) {
                cRLGeneralNameList.add(new GeneralName(new X500Name(distributionPoint.getCRLIssuer())));
                final GeneralNames cRLGeneralNames = new GeneralNames(cRLGeneralNameList.toArray(new GeneralName[0]));
                distributionPointNames.add(new org.bouncycastle.asn1.x509.DistributionPoint(null, reasonFlag, cRLGeneralNames));
            }
        }
        final CRLDistPoint cRLDistPoint = new CRLDistPoint(distributionPointNames.toArray(new org.bouncycastle.asn1.x509.DistributionPoint[0]));
        final DEROctetString cRLDistributionPointExtension = new DEROctetString(cRLDistPoint);

        return cRLDistributionPointExtension;
    }
}
