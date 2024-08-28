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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.CSRUtil;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;

@RunWith(MockitoJUnitRunner.class)
public class CertMgmtRenewAndModifyEntityHandlerTest {
    @InjectMocks
    CertMgmtRenewAndModifyEntityHandler certMgmtRenewAndModifyEntityHandler;

    @Mock
    CliUtil cliUtil;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    EntityCertificateManagementService endEntityCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CSRUtil csrUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertMgmtRenewAndModifyEntityHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    CertificateRequest certRequest;
    String content = "";

    Map<String, Object> properties = new HashMap<String, Object>();
    Certificate certificate = new Certificate();
    List<Certificate> certificates = new ArrayList<Certificate>();
    X509Certificate x509Certificate;

    /**
     * @throws java.lang.Exception
     */

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        final URL url = Thread.currentThread().getContextClassLoader().getResource("CSR.csr");
        final URL url1 = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");

        final String filename = url1.getFile();

        final String filePath = URLDecoder.decode(filename);
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYCERTMANAGEMENTREISSUE);
        command.setProperties(properties);

        String lines = "";

        final BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
        while ((lines = br.readLine()) != null) {
            content += lines + Constants.NEXT_LINE;
        }
        certRequest = BaseTest.generateCertificateRequest(content);
        Mockito.when(cliUtil.getFileContentFromCommandProperties(properties)).thenReturn(content);
        x509Certificate = BaseTest.getCertificate(filePath);
        certificate.setX509Certificate(x509Certificate);

        Mockito.doNothing().when(exportedItemsHolder).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getEntityCertificateManagementService()).thenReturn(endEntityCertificateManagementService);

    }

    @Test
    public void tesRenewAndModifyHandler() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, EntityNotFoundException, InvalidCAException,
            InvalidCertificateRequestException, InvalidEntityException, CertificateEncodingException, IOException {
        properties.put("entityname", "RBS1234");
        properties.put("status", "active");
        command.setProperties(properties);

        Mockito.when(endEntityCertificateManagementService.renewCertificate("RBS1234", certRequest)).thenReturn(certificate);
        final PkiCommandResponse pkiCommandResponse = certMgmtRenewAndModifyEntityHandler.renewAndModifyHandler(command, "RBS1234");

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

}
