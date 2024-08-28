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

import com.ericsson.cds.cdi.support.configuration.InjectionProperties
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData

import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.util.Map

import javax.inject.Inject
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext
import javax.persistence.PersistenceException
import javax.persistence.Query
import javax.persistence.criteria.CriteriaBuilder
import org.slf4j.Logger
/**
 * This class Mock the EntityManager,PersistenceManager and prepares the test data for to Publish CRL's using list of CRLInfo's and Unpublish CRL's using list of CACertificateInfo's to CDPS DB.
 * 
 * @author xchowja
 *
 */
public class AbstractBaseSpec extends CdiSpecification {

	@MockedImplementation
	PersistenceManager persistenceManager

	EntityManager entityManager
	Query query

	/**
	 * Customize the injection provider
	 * */
	@Override
	public Object addAdditionalInjectionProperties(InjectionProperties injectionProperties) {
		injectionProperties.autoLocateFrom('com.ericsson.oss.itpf.security.pki.cdps.local.service.ejb')
	}

	List<CDPSEntityData> cdpsEntityDataList = new ArrayList<CDPSEntityData>();
	TestCRLSetUpData testCRLSetUpData
	def setup(){
		entityManager = Stub(EntityManager.class)
		query = Stub(Query.class)
		testCRLSetUpData = new TestCRLSetUpData()
	}

	def List<CRLInfo> setUpData(final String caName, final String serialNumber, final String filePath){
		persistenceManager.getEntityManager() >> entityManager
		persistenceManager.getEntityManager().createNamedQuery("CDPSEntityData.findByCaNameAndSerialNumber") >> query
		cdpsEntityDataList.add(testCRLSetUpData.getCRLSetUpData(caName,serialNumber,filePath))
		query.setParameter("caName", caName) >> query
		query.setParameter("serialNumber", serialNumber) >> query
		if(caName ==null || serialNumber==null) {
			query.getResultList() >> {throw new PersistenceException("Error occured during DB operations")}
		}else{
			if(caName.equalsIgnoreCase("ENM_NBI_CA")){
				query.getResultList() >> new ArrayList<CDPSEntityData>()
			}else{
				query.getResultList() >> cdpsEntityDataList
			}
		}

		return testCRLSetUpData.getCRLInfoList(caName,serialNumber,filePath)
	}
}
