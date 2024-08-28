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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.IssuingDistributionPoint;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.CRLSetUpData;

/**
 * Test Class for IssuingDistributionPointsBuilder.
 */
@RunWith(MockitoJUnitRunner.class)
public class IssuingDistributionPointsBuilderTest {

	@InjectMocks
	IssuingDistributionPointsBuilder issuingDistributionPointsBuilder;

	@Mock
	Logger logger;

	@Mock
	X500Name x500Name;

	@Mock
	GeneralNames generalNames;

	private static CrlGenerationInfo crlGenerationInfo;
	private static IssuingDistributionPoint issuingDistributionPoint;
	private static List<ReasonFlag> reasonFlags = new ArrayList<ReasonFlag>();
	public static final ASN1ObjectIdentifier subjectDirectoryAttributes = new ASN1ObjectIdentifier(
			"2.5.29.28");

	/**
	 * Prepares initial Data.
	 */
	@Before
	public void setUpData() {
		issuingDistributionPoint = CRLSetUpData.getIssuingDistributionPoint();
		crlGenerationInfo = com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.CRLSetUpData
				.getCrlGenerationInfo();

	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * SUPERSEDED.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_SUPERSEDED() {
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * AA_COMPROMISE.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_AA_COMPROMISE() {

		reasonFlags.add(ReasonFlag.AA_COMPROMISE);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * AFFILIATION_CHANGED.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_AFFILIATION_CHANGED() {

		reasonFlags.add(ReasonFlag.AFFILIATION_CHANGED);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * CA_COMPROMISE.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_CA_COMPROMISE() {

		reasonFlags.add(ReasonFlag.CA_COMPROMISE);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * CERTIFICATE_HOLD.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_CERTIFICATE_HOLD() {

		reasonFlags.add(ReasonFlag.CERTIFICATE_HOLD);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * CESSATION_OF_OPERATION.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_CESSATION_OF_OPERATION() {

		reasonFlags.add(ReasonFlag.CESSATION_OF_OPERATION);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * KEY_COMPROMISE.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_KEY_COMPROMISE() {

		reasonFlags.add(ReasonFlag.KEY_COMPROMISE);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is
	 * PRIVILEGE_WITHDRAWN.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_PRIVILEGE_WITHDRAWN() {

		reasonFlags.add(ReasonFlag.PRIVILEGE_WITHDRAWN);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when reasonFlag is UNUSED.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_UNUSED() {

		reasonFlags.add(ReasonFlag.UNUSED);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}

	/**
	 * Method to test buildIssuingDistributionPoint when When FullName is Null.
	 */
	@Test
	public void testBuildIssuingDistributionPoint_WhenFullNameIsNull() {
		issuingDistributionPoint.getDistributionPoint().setFullName(null);
		crlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(
				issuingDistributionPoint);
		Extension extension = issuingDistributionPointsBuilder
				.buildIssuingDistributionPoint(crlGenerationInfo);
		assertNotNull(extension);
		assertEquals(false, extension.isCritical());
		assertEquals(subjectDirectoryAttributes, extension.getExtnId());
	}
}
