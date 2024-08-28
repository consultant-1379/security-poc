package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.FailureResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;

@RunWith(MockitoJUnitRunner.class)
public class ErrorResponseBuilderTest {

    @InjectMocks
    ErrorResponseBuilder failureResponseBuilder;

    @Mock
    FailureResponseMessage failureResponseMessage;

    @Mock
    Logger logger;

    @Mock
    X509Certificate x509Certificate;

    private static final String ERROR_MESSAGE = "UNEXPECTED_ERROR";

    private static RequestMessage pKIRequestMessage;
    private static String transactionID = null;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        Parameters requestParameters = AbstractMain.configureParameters(null);
        PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.INITIALIZATION_REQUEST).generate(requestParameters, null);

        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        transactionID = pKIRequestMessage.getBase64TransactionID();
    }

    @Test
    public void testBuildResponseEvent() throws IOException {
        failureResponseBuilder.build(ERROR_MESSAGE, transactionID, pKIRequestMessage, null);
        assertThat(failureResponseMessage, instanceOf(FailureResponseMessage.class));
    }

    @Test
    public void testBuildResponseEventx509CertificateNotNull() throws IOException, java.security.cert.CertificateException {

        //String cert = "MIIDTjCCAjagAwIBAgIHMzT/j2HMiTANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDApFTk1fT0FNX0NBMB4XDTE1MDkwNDA2NTMyM1oXDTIzMDkwNDA2NTMyM1owXjEWMBQGA1UECwwNQlVDSV9EVUFDX05BTTERMA8GA1UECgwIRVJJQ1NTT04xJDAiBgNVBAMMG3N2Yy0xLXBraXJhc2Vydl9DTVBSQVNFUlZFUjELMAkGA1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCFOyvy8ydqD7KPxsOEq9ldb3kvhq8hATKRONDJPGB8dvbGLtA2Xo6ZxT4+WaVCxCw+dTprfNivV6zwPspmXnuqhALAv1SCeeBCpUMJTVuwzrsc/BqEefx2AKjdiwur1U+VPnAV2GV1Lo2kM50g98SYDyJOOpobCq4bhvbuxKN8kFHrw0LGF/E7hwBr5T8r1kPCdt3aYSMvmxMGi7gFp8rjuRvg3VoFJIrJtSay6JPyj2y+KPbCjG3BTvuDlWeW47/wV4R9RDjRYpdotleHrJMRx+Q691iPAI4kI19k2eO9b0ERvmZ7MXV1fEgc53+8kBu6MRmOSCx0r0kg9CS4l2yFAgMBAAGBAgeAggIHgKNSMFAwHwYDVR0jBBgwFoAU50al/zFguKBGt+HN15zsIlDilUMwHQYDVR0OBBYEFMQ8QZH6opu9xacTGsLulGHyrkY0MA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQsFAAOCAQEAdCOZ1TSRH2yXmkrTBvFnTeh/VAohqTMfbKyixs/V3scID9Hm3CHB9FLptmZFAg5dnLWq790uzYUop+zXvJh/kQDjnEmt2P5MsDLOrZKPi/GjtYA2qUxgp01AFVO+VqgwTC65JLXNzkbW9djlsD2zeujTCgOuH/8XO+y/DV2VsnfV6eiYvchx/6kWnow9cBu5OTzNiwJ0Qe4IY82VWfiWob0F/0iAjg57H5VMWMq3Ypsim4/3lcyBDmUJuOMIqF5RFU+BoXfsFE67wdjX6Dsz5CQvAt+DU5cdROHKLRwf+Uh1gZfxD972VUFpu6h4Ei2omm+jOqnV5LJ/CNQqrZzkMQ==";

        byte[] encoded = getCMPCerts();
        Mockito.when(x509Certificate.getEncoded()).thenReturn(encoded);

        failureResponseBuilder.build(ERROR_MESSAGE, transactionID, pKIRequestMessage, x509Certificate);
        assertThat(failureResponseMessage, instanceOf(FailureResponseMessage.class));
    }

    public static byte[] getCMPCerts() throws FileNotFoundException, java.security.cert.CertificateException {
        CertificateFactory certificateFactory;
        X509Certificate tDPSCert;
        FileInputStream fileInputStream;
        String tDPSCertPath = null;

        tDPSCertPath = ErrorResponseBuilderTest.class.getResource("/Certificates/verifyDigiSignature_vendorCerts/factory.crt").getPath();
        certificateFactory = CertificateFactory.getInstance("X.509");
        fileInputStream = new FileInputStream(tDPSCertPath);
        tDPSCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);

        return tDPSCert.getEncoded();
    }

}
