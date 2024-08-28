package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.kur;

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

import com.ericsson.oss.itpf.security.pki.common.cmp.model.KeyUpdateResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateResponseMessageBuilder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ResponseBuilderMockUtil;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir.InitializationResponseBuilderTest;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.CMPServiceResponse;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CertificateResponseMessageBuilder.class)
public class KeyUpdateResponseBuilderTest {

    @InjectMocks
    KeyUpdateResponseBuilder keyUpdateResponseEventBuilder;

    @Mock
    EntityCertificateManagementService endEntityCertificateManagementService;

    @Mock
    CMPServiceResponse cMPServiceResponse;

    @Mock
    KeyUpdateResponseMessage keyUpdateResponseMessage;

    @Mock
    Logger logger;
    @Mock
    CertRepMessage certRepMsg;

    private static String transactionID = null;
    private static String entityCN = "Entity";
    private static String rAKeyAndCertPath = null;
    private static CertDataHolder certDataHolder = null;
    private static CertificateRequest csr;
    private static RequestMessage pKIKeyUpdateRequestMessage;

    Certificate userCert;
    List<X509Certificate> trustedCerts;
    CertificateChain certChain;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.KEY_UPDATE_REQUEST).generate(requestParameters, null);

        pKIKeyUpdateRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionID = pKIKeyUpdateRequestMessage.getBase64TransactionID();
        rAKeyAndCertPath = InitializationResponseBuilderTest.class.getResource("/CertificatesTest/" + "racsa_omsas.jks").getPath();
        certDataHolder = CertDataHolder.getRACertDataHolder(rAKeyAndCertPath);
        csr = ResponseBuilderMockUtil.generateCSR(pKIKeyUpdateRequestMessage.getPKIBody());
    }

    @Test
    public void testBuild() throws Exception {
        userCert = ResponseBuilderMockUtil.getUSerCertificate(certDataHolder);
        trustedCerts = ResponseBuilderMockUtil.getX509TrsutedCertificates(userCert);
        PowerMockito.mockStatic(CertificateResponseMessageBuilder.class);
        int certRequestID = 1;
        Mockito.when(CertificateResponseMessageBuilder.build(certRequestID, userCert.getX509Certificate(), trustedCerts)).thenReturn(certRepMsg);
        keyUpdateResponseEventBuilder.build(pKIKeyUpdateRequestMessage, transactionID, userCert.getX509Certificate(), trustedCerts, trustedCerts);

    }
}