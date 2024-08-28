/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.cdps.ejb;

import static org.junit.Assert.*

import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.util.List

import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.*
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLExpiredException
import javax.persistence.PersistenceException

import org.bouncycastle.util.encoders.Base64

import spock.lang.Specification
import spock.lang.Unroll
/**
 * This class covers positive and scenario test cases for to get the CRL's from CDPS DB based on caName and certSerialNumber.
 *
 * @author xchowja
 *
 */
public class CRLDistributionPointServiceTest extends AbstractBaseSpec {

	@ObjectUnderTest
	CRLDistributionPointServiceBean crlDistributionPointServiceBean

	@Unroll("Getting the CRL from db for valid caName #CAName and certSerialNumber #CertSerialNumber ")
	def "Getting the CRL from db for valid caName and certSerialNumber"() {
		given :"setup data for getting crls"
		def caName = CAName
		def certSerialNumber = CertSerialNumber
		def crlFilePath = CRLFilePath
		setCDPSEntityData(caName,certSerialNumber,crlFilePath);
		when: " to retrieve crls from DB using the crlDistributionPointServiceBean"
		byte[] crlByteArray = crlDistributionPointServiceBean.getCRL(caName, certSerialNumber)
		if (StringUtility.isBase64(new String(crlByteArray))) {
			crlByteArray = Base64.decode(crlByteArray);
		}
		final X509CRL x509crl = getOutputX509CRL(crlByteArray)
		then: "assert CRL response"
		x509crl.getIssuerDN().toString() == ExpectedMessage
		where : "Multiple inputs supplied to get the crl"
		CAName               |     CertSerialNumber   | CRLFilePath                                 | ExpectedMessage
		'NE_OAM_CA'          |     '622d457a161ff66a' | 'src/test/resources/crls/NE_OAM_CA.crl'     | 'C=SE, O=ERICSSON, OU=BUCI_DUAC_NAM, CN=NE_OAM_CA'
		'NE_IPSEC_CA'        |     '6232d09ee615a6fb' | 'src/test/resources/crls/NE_IPsec_CA.crl'   | 'C=SE, O=ERICSSON, OU=BUCI_DUAC_NAM, CN=NE_IPsec_CA'
	}

	@Unroll("Getting the CRL from db for invalid caName #CAName and certSerialNumber #CertSerialNumber ")
	def "Getting the CRL from db for invalid caName and certSerialNumber"() {
		given :"setup data for getting crls"
		def caName = CAName
		def certSerialNumber = CertSerialNumber
		def crlFilePath = CRLFilePath
		setInvalidCDPSEntityData(caName,certSerialNumber,crlFilePath)
		when: " to retrieve crls from DB using the crlDistributionPointServiceBean"
		byte[] crlByteArray = crlDistributionPointServiceBean.getCRL(caName, certSerialNumber)
		then: "assert CRL response"
		def error = thrown(ExpectedException)
		error.message == ExpectedMessage
		where : "Multiple inputs supplied to get the crl for negative scenarios"
		CAName         |     CertSerialNumber   |  CRLFilePath                               |    ExpectedException                    | ExpectedMessage
		'ENM_OAM_CA'   |    '342354745747'      | 'src/test/resources/crls/InvalidCACrl.crl' |    InvalidCRLException  				   | 'Requested CRL is Expired'
		null           |     'tets3434333'      | 'src/test/resources/crls/InvalidCACrl.crl' |    CRLNotFoundException                 | 'Couldn\'t find the crl with the given caName and certSerialNumber'
		'ENM_NBI_CA'   |     '41dfgdfg24323434' | 'src/test/resources/crls/ENM_NBI_CA.crl'   |    InvalidCRLException                  | 'Exception while converting the CRL byte array into X509CRL'
		'ENM_E-mail_CA'|     '23bbcb1f509e28fe' | null                                       |    CRLDistributionPointServiceException | 'Exception occured while retrieving the CRL'
	}
}
