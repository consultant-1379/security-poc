package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateResponseMessageBuilder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ResponseBuilderMockUtil;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CertificateResponseMessageBuilder.class)
public class InitializationResponseBuilderTest {

    @InjectMocks
    InitializationResponseBuilder initializationResponseEventBuilder;

    @Mock
    EntityCertificateManagementService endEntityCertificateManagementService;

    @Mock
    Certificate certificate;

    @Mock
    CertificateChain certificateChain;

    @Mock
    ResponseMessage iPResponseMessage;

    @Mock
    Logger logger;

    @Mock
    CertRepMessage certRepMsg;

    @Mock
    RequestMessage pKIRequestMessage;

    private static RequestMessage pKIInitializationRequestMessage;
    private static String transactionID = null;
    private static String rAKeyAndCertPath = null;
    private static CertDataHolder certDataHolder = null;
    private static CertificateRequest csr;

    Certificate userCert;
    List<X509Certificate> trustedCerts;
    CertificateChain certChain;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        pKIInitializationRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionID = pKIInitializationRequestMessage.getBase64TransactionID();
        rAKeyAndCertPath = InitializationResponseBuilderTest.class.getResource("/CertificatesTest/" + "racsa_omsas.jks").getPath();
        certDataHolder = CertDataHolder.getRACertDataHolder(rAKeyAndCertPath);
        csr = ResponseBuilderMockUtil.generateCSR(pKIInitializationRequestMessage.getPKIBody());
    }

    @Test
    public void testBuild() throws Exception {
        userCert = ResponseBuilderMockUtil.getUSerCertificate(certDataHolder);
        PowerMockito.mockStatic(CertificateResponseMessageBuilder.class);
        int certRequestID = 1;
        trustedCerts = ResponseBuilderMockUtil.getX509TrsutedCertificates(userCert);
        Mockito.when(CertificateResponseMessageBuilder.build(certRequestID, userCert.getX509Certificate(), trustedCerts)).thenReturn(certRepMsg);

        initializationResponseEventBuilder.build(pKIInitializationRequestMessage, transactionID, userCert.getX509Certificate(), trustedCerts, trustedCerts);

    }

}