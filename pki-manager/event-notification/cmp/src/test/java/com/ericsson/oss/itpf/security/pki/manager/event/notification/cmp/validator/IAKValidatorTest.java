package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.validator;

import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.IAKParameters;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.test.request.generator.RequestGeneratorFactory;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPNotSetException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.EntityManagementLocalService;

@Ignore
@RunWith(MockitoJUnitRunner.class)
public class IAKValidatorTest {

    @InjectMocks
    IAKValidator iakValidator;

    @Mock
    EntityManagementLocalService entityManagementLocalService;

    @Mock
    Logger logger;

    @Mock
    IAKParameters iakParameters;

    private static final String ADMIN = "admin";
    private static final String ENTITY_NAME = "Entity";
    private static RequestMessage pKIRequestMessage;
    private static RequestMessage pKIRequestMessageWithWrongSignature;

    @BeforeClass
    public static void prepareTestData() throws Exception {
        final Parameters requestParameters = AbstractMain.configureParameters(null);
        final PKIMessage pkiRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.IAK_REQUEST).generate(requestParameters, null);
        pKIRequestMessage = new RequestMessage(pkiRequestMessage.getEncoded());
        requestParameters.setValidIAK(false);
        final PKIMessage pkiIakRequestMessage = RequestGeneratorFactory.getRequestGenerator(RequestType.IAK_REQUEST).generate(requestParameters, null);
        pKIRequestMessageWithWrongSignature = new RequestMessage(pkiIakRequestMessage.getEncoded());
    }

    @Test
    public void testVerifyPasswordBasedMac() {

        Mockito.when(entityManagementLocalService.getOTP(ENTITY_NAME)).thenReturn("12345");
        Mockito.when(entityManagementLocalService.getOTP(ENTITY_NAME)).thenReturn(ADMIN);

        iakValidator.verifyPasswordBasedMac(ENTITY_NAME, pKIRequestMessage);

        Mockito.verify(entityManagementLocalService).getOTP(ENTITY_NAME);

    }

    @Test
    public void testVerifyPasswordBasedMacEntityNotFoundException() {
        Mockito.when(entityManagementLocalService.getOTP(ENTITY_NAME)).thenReturn(ADMIN);

        iakValidator.verifyPasswordBasedMac(ENTITY_NAME, pKIRequestMessage);

        Mockito.verify(entityManagementLocalService).getOTP(ENTITY_NAME);

    }

    @Test(expected = IAKValidationException.class)
    public void testVerifyPasswordBasedMacException() {
        Mockito.when(entityManagementLocalService.getOTP(ENTITY_NAME)).thenReturn(ADMIN);

        iakValidator.verifyPasswordBasedMac(ENTITY_NAME, pKIRequestMessageWithWrongSignature);

        Mockito.verify(entityManagementLocalService).getOTP(ENTITY_NAME);

    }

    @Test(expected = IAKValidationException.class)
    public void testVerifyPasswordBasedMacIllegalStateException() {

        Mockito.when(entityManagementLocalService.getOTP(ENTITY_NAME)).thenThrow(new IllegalStateException());
        iakValidator.verifyPasswordBasedMac(ENTITY_NAME, pKIRequestMessageWithWrongSignature);

        Mockito.verify(entityManagementLocalService).getOTP(ENTITY_NAME);

    }

    @Test(expected = IAKValidationException.class)
    public void testVerifyPasswordBasedMacExceptionEntityNotFoundException() {

        Mockito.when(entityManagementLocalService.getOTP(ENTITY_NAME)).thenThrow(new OTPNotSetException());
        iakValidator.verifyPasswordBasedMac(ENTITY_NAME, pKIRequestMessageWithWrongSignature);

        Mockito.verify(entityManagementLocalService).getOTP(ENTITY_NAME);

    }

}
