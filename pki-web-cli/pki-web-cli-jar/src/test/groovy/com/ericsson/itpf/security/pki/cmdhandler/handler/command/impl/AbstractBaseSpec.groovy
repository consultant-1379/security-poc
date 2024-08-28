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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import com.ericsson.cds.cdi.support.configuration.InjectionProperties
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.custom.EntityCertificateManagementCustomService
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.custom.secgw.SecGWCertificates
import java.net.URLDecoder
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Path
import java.util.ArrayList
import java.util.List

import javax.inject.Inject

/**
 * This class prepares data to initiate the SecurityGatewayManagementGenerateHandler
 * 
 *@author zvetsni
 */

public class AbstractBaseSpec extends CdiSpecification {

    @Inject
    PkiPropertyCommand command

    @MockedImplementation
    FileUtility fileUtil

    @MockedImplementation
    ExportedItemsHolder exportedItemsHolder

    @Inject
    EntityCertificateManagementCustomService entityCertificateManagementCustomService

    @Inject
    TestSetupInitializer testSetupInitializer

    final Map<String, Object> properties = new HashMap<String,Object>()
    final List<Certificate> certificateList = new ArrayList<Certificate>()
    SecGWCertificates secGwCertificates = new SecGWCertificates()
    CertificateChain certificateChain = new CertificateChain()

    def final certType_OAM = "OAM"
    def final certType_Traffic = "Traffic"
    /**
     * Customize the injection provider
     * 
     */
    @Override
    public Object addAdditionalInjectionProperties(final InjectionProperties injectionProperties) {
        injectionProperties.autoLocateFrom('com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl')
    }

    /**
     * This method separates the filename from filePath and generate certificates
     * 
     */
    def setup(){
        System.setProperty("file.separator","/")
    }

    def final setCertData(final String certType, final String filePath, final String certFile){
        def supportedCertTypes = new ArrayList<String>()
        supportedCertTypes.add(certType_OAM)
        supportedCertTypes.add(certType_Traffic)
        properties.put("filePath", filePath)
        command.setCommandType(PkiCommandType.SECGWCERTMANAGEMENT)
        command.setProperties(properties)
        command.setValueString(Constants.CERT_TYPE, certType)
        command.setValueString(Constants.NOCHAIN,"nochain")
        def osAppropriatePath = command.setValue(Constants.FILE_SEPARATOR,filePath)
        final Certificate secGwCertificate = testSetupInitializer.getSecGwCert(certFile)
        certificateList.add(secGwCertificate)
        certificateChain.setCertificateChain(certificateList)
        secGwCertificates.setCertificate(secGwCertificate)
        secGwCertificates.setCertificateChain(certificateChain)
        secGwCertificates.setTrustedCertificates(certificateList)
        entityCertificateManagementCustomService.generateSecGWCertificate(_,_,_) >> secGwCertificates
    }
}
