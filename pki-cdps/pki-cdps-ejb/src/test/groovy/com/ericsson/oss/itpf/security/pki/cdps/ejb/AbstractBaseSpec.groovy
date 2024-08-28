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
package com.ericsson.oss.itpf.security.pki.cdps.ejb

import com.ericsson.cds.cdi.support.configuration.InjectionProperties
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.PersistenceManager
import com.ericsson.oss.itpf.security.pki.cdps.common.persistence.entity.CDPSEntityData
import java.security.cert.X509CRL
import javax.inject.Inject
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext
import javax.persistence.PersistenceException
import javax.persistence.criteria.CriteriaBuilder
/**
 * Class is responsible to prepare setup data to get CRL's.
 * 
 * @author xchowja
 *
 */
public class AbstractBaseSpec extends CdiSpecification {

	@MockedImplementation
	PersistenceManager persistenceManager

	/**
	 * Customize the injection provider
	 * */
	@Override
	public Object addAdditionalInjectionProperties(InjectionProperties injectionProperties) {
		injectionProperties.autoLocateFrom('com.ericsson.oss.itpf.security.pki.cdps.ejb')
	}

	private List<CDPSEntityData> cdpsCrlEntityList = new ArrayList<CDPSEntityData>()

	TestCRLSetUpData testCRLSetUpData
	Map<String, Object> parameters

	def setup(){
		parameters = new HashMap<String, Object>()
		testCRLSetUpData = new TestCRLSetUpData()
	}

	def setCDPSEntityData(final String caName,final String certSerialNumber,final String filePath) {
		parameters.put( "caName", caName)
		parameters.put("certSerialNumber", certSerialNumber)
		cdpsCrlEntityList.add(testCRLSetUpData.getCRLSetUpData(caName,certSerialNumber,filePath));
		persistenceManager.findEntitiesWhere(CDPSEntityData.class,parameters) >> cdpsCrlEntityList
	}

	def setInvalidCDPSEntityData(final String caName,final String certSerialNumber,final String filePath) {
		parameters.put( "caName", caName)
		parameters.put("certSerialNumber", certSerialNumber)
		if(caName != null && certSerialNumber != null){
			if(filePath !=null){
				cdpsCrlEntityList.add(testCRLSetUpData.getCRLSetUpData(caName,certSerialNumber,filePath));
				persistenceManager.findEntitiesWhere(CDPSEntityData.class,parameters) >> cdpsCrlEntityList
			}else{
				persistenceManager.findEntitiesWhere(_,_) >> { throw new PersistenceException()}
			}
		}else{
			persistenceManager.findEntitiesWhere(CDPSEntityData.class,parameters) >> cdpsCrlEntityList
		}
	}

	def X509CRL getOutputX509CRL(final byte[] crlByteArray){
		return testCRLSetUpData.getX509CRL(crlByteArray);
	}
}
