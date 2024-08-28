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
package com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb;

import javax.persistence.Query

import com.ericsson.cds.cdi.support.configuration.InjectionProperties
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.constants.Constants
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.CertificateNotFoundException
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.DataLookupException
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.PersistenceManager
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData

/**
 * This class prepares setupdata to retrieve the certificate from TDPS DB
 *
 *  @author zkakven
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
        injectionProperties.autoLocateFrom('com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb')
    }

    TestSetupInitializer testSetupInitializer
    byte[] trustCertBasedOnCAName

    def setup(){
        testSetupInitializer = new TestSetupInitializer()
    }

    def setTDPSEntityData(final TrustDistributionParameters trustDistributionParameters, final String filePath) {
        if(filePath !=null && trustDistributionParameters.getEntityName()!=null){
            trustCertBasedOnCAName = testSetupInitializer.getTDPSCert(filePath)
            persistenceManager.getCertificate(trustDistributionParameters.getEntityName(), trustDistributionParameters.getEntityType(),
                    trustDistributionParameters.getIssuerName(), trustDistributionParameters.getCertificateStatus(), trustDistributionParameters.getCertificateSerialId()) >> trustCertBasedOnCAName
        }
        else if(filePath !=null && trustDistributionParameters.getEntityName() == null){
            persistenceManager.getCertificate(trustDistributionParameters.getEntityName(), trustDistributionParameters.getEntityType(),
                    trustDistributionParameters.getIssuerName(), trustDistributionParameters.getCertificateStatus(), trustDistributionParameters.getCertificateSerialId()) >> { throw new CertificateNotFoundException() }
        }
        else {
            persistenceManager.getCertificate(trustDistributionParameters.getEntityName(), trustDistributionParameters.getEntityType(),
                    trustDistributionParameters.getIssuerName(), trustDistributionParameters.getCertificateStatus(), trustDistributionParameters.getCertificateSerialId()) >> { throw new DataLookupException() }
        }
    }
}
