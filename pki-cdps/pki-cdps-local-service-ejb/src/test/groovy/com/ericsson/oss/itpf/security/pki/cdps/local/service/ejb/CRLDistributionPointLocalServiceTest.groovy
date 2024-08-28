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
package com.ericsson.oss.itpf.security.pki.cdps.local.service.ejb

import java.util.List

import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.*

import spock.lang.Unroll

/**
 * This class covers positive and scenario test cases for to Publish CRL's using list of CRLInfo's and Unpublish CRL's using list of CACertificateInfo's to CDPS DB.
 * 
 * @author xchowja
 *
 */
public class CRLDistributionPointLocalServiceTest extends AbstractBaseSpec{

	@ObjectUnderTest
	CRLDistributionPointLocalServiceBean crlDistributionPointLocalServiceBean

	@Unroll("Publish the CRL's using list of CRLInfo's and Unpublish CRL's using list of CACertificateInfo's to CDPS database for valid CAName #CAName and CertSerialNumber #CertSerialNumber")
	def "Publish the CRL's using list of CRLInfo's and Unpublish CRL's using list of CACertificateInfo's "() {
		given :"setup data"
		final List<CRLInfo> crlInfoList = setUpData(CAName,CertSerialNumber,CRLFilePath)
		def error
		when: "to Publish and CRL's using list of CRLInfo's to CDPS database"
		crlDistributionPointLocalServiceBean.publishCRL(crlInfoList)
		then: "assert Publish response"
		when: "to Unpublish CRL's using list of CACertificateInfo's to CDPS database"
		final List<CACertificateInfo> caCertificateInfos= new ArrayList<CACertificateInfo>()
		caCertificateInfos << crlInfoList.get(0).getCaCertificateInfo()
		crlDistributionPointLocalServiceBean.unPublishCRL(caCertificateInfos)
		then: "assert UnPublish response"
		where : "Multiple inputs supplied to Publish or UnPublish crl's"
		CAName               |     CertSerialNumber   | CRLFilePath                               | ExpectedException                    | ExpectedMessage
		'NE_OAM_CA'          |     '622d457a161ff66a' | 'src/test/resources/crls/NE_OAM_CA.crl'   | null                                 | null
		'ENM_NBI_CA'         |     '41dfgdfg24323434' | 'src/test/resources/crls/ENM_NBI_CA.crl'  | null                                 | null
		'NE_IPSEC_CA'        |     '6232d09ee615a6fb' | 'src/test/resources/crls/NE_IPsec_CA.crl' | null                                 | null
	}

	@Unroll("Publish the CRL's using list of CRLInfo's and Unpublish CRL's using list of CACertificateInfo's to CDPS for invalid or empty CAName #CAName and CertSerialNumber #CertSerialNumber")
	def "Publish the CRL's using list of CRLInfo's and Unpublish CRL's using list of CACertificateInfo's for CRLDistributionPointServiceException"() {
		given :"setup data"
		final List<CRLInfo> crlInfoList = setUpData(CAName,CertSerialNumber,CRLFilePath)
		def error
		final List<CACertificateInfo> caCertificateInfos= new ArrayList<CACertificateInfo>()
		when: "to Publish and CRL's using list of CRLInfo's to CDPS database"
		crlDistributionPointLocalServiceBean.publishCRL(crlInfoList)
		then: "assert Publish response"
		error = thrown(ExpectedException)
		error.message == ExpectedMessage
		when: "to Unpublish CRL's using list of CACertificateInfo's to CDPS database"
		caCertificateInfos << crlInfoList.get(0).getCaCertificateInfo()
		crlDistributionPointLocalServiceBean.unPublishCRL(caCertificateInfos)
		then: "assert UnPublish response"
		error = thrown(ExpectedException)
		error.message == ExpectedMessage
		where : "Multiple inputs supplied to Publish or UnPublish crl's"
		CAName               |     CertSerialNumber   | CRLFilePath                              | ExpectedException                    | ExpectedMessage
		'NE_OAM_CA'          |     null               | 'src/test/resources/crls/NE_OAM_CA.crl'  | CRLDistributionPointServiceException | 'Error occured during DB operations'
		null                 |     '6232d09ee615a6fb' | 'src/test/resources/crls/NE_IPsec_CA.crl'| CRLDistributionPointServiceException | 'Error occured during DB operations'
	}
}
