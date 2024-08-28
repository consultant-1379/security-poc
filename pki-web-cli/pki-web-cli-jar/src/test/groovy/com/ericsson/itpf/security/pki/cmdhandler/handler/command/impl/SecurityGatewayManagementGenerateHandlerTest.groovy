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

import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

import javax.inject.Inject

import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility

/**
 * This class covers positive and negative scenarios for Security Gateway Handler using the following parameter 
 * 
 * @author zvetsni
 */

public class SecurityGatewayManagementGenerateHandlerTest extends AbstractBaseSpec{

    @ObjectUnderTest
    SecurityGatewayManagementGenerateHandler securityGatewayManagementGenerateHandler

    @Inject
    TestSetupInitializer testSetupInitializer

    @Unroll("Positive scenarios for handling Secure Gateway using certType #certTypeNames as input")
    def "Process Security Gateway Handler to download a zip file"(){
        given:"certTypeNames, filePath and certFile "
        setCertData(certTypeNames,filePath,certFile)
        when:"execute process"
        def response = securityGatewayManagementGenerateHandler.process(command)
        then:"verifying the response with message"
        assert response.getResponseType(), ExpectedMessage
        where:
        certTypeNames   |filePath                       |certFile       |ExpectedMessage
        "OAM"           |"src/test/resources/CSR.csr"   |"MyRoot.crt"   |PKICommandResponseType.DOWNLOAD_REQ
        "Traffic"       |"src/test/resources/CSR.csr"   |"MyRoot.crt"   |PKICommandResponseType.DOWNLOAD_REQ
    }

    @Unroll("Negative scenarios for handling Secure Gateway using certType #certTypeNames as input")
    def "Security Gateway throws exceptions at the time of downloading a zip file"(){
        given: "file, certTypeName and ExpectedMessage"
        setCertData(certTypeName,file,certFile)
        when:"execute process"
        def result = securityGatewayManagementGenerateHandler.process(command)
        then:"verifying the response with the expected message"
        assert result.getResponseType(), ExpectedMessage
        where:
        file                                        |certTypeName   |certFile           |ExpectedMessage
        "src/test/resources/CSR.csr"                |null           |"MyRoot.crt"       |PKICommandResponseType.MESSAGE
        "src/test/resources/InvalidContent.csr"     |"OAM"          |"MyRoot.crt"       |PKICommandResponseType.MESSAGE
        "src/test/resources/EmptyCSRFile.csr"       |"OAM"          |"MyRoot.crt"       |PKICommandResponseType.MESSAGE
    }
}
