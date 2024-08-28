package com.ericsson.oss.itpf.security.credmsapi.test.exceptions;

import java.lang.reflect.InvocationTargetException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.AlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateValidationException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ConfigurationException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetEndEntitiesByCategoryException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCategoryNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCertificateFormatException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReIssueLegacyXMLCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReissueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeEntityCertificateException;

@RunWith(MockitoJUnitRunner.class)
public class CredmsApiExceptionsTest {

    @Test
    public void ExceptionsTest() {
        this.exceptionClassTest(CertificateValidationException.class);
        
        this.exceptionClassTest(ConfigurationException.class);

        this.exceptionClassTest(EntityNotFoundException.class);

        this.exceptionClassTest(GetEndEntitiesByCategoryException.class);

        this.exceptionClassTest(InvalidCategoryNameException.class);

        this.exceptionClassTest(InvalidCertificateFormatException.class);

        this.exceptionClassTest(IssueCertificateException.class);

        this.exceptionClassTest(OtpExpiredException.class);

        this.exceptionClassTest(OtpNotValidException.class);

        this.exceptionClassTest(ReissueCertificateException.class);

        this.exceptionClassTest(RevokeCertificateException.class);
        
        this.exceptionClassTest(AlreadyRevokedCertificateException.class);
        
        this.exceptionClassTest(CertificateNotFoundException.class);
        
        this.exceptionClassTest(ExpiredCertificateException.class);
        
        this.exceptionClassTest(GetCertificatesByEntityNameException.class);

        this.exceptionClassTest(RevokeEntityCertificateException.class);
        
        this.exceptionClassTest(ReIssueLegacyXMLCertificateException.class);
        
    }
    
    private <T> void exceptionClassTest(Class<T> tex) {
        try {
            T e1 = tex.newInstance();
            Assert.assertNotNull(e1);
            T e2 = tex.getDeclaredConstructor(String.class).newInstance("msg");
            Assert.assertNotNull(e2);
            T e3 = tex.getDeclaredConstructor(Throwable.class).newInstance(e1);
            Assert.assertNotNull(e3);
            T e4 = tex.getDeclaredConstructor(String.class, Throwable.class).newInstance("msg",e1);
            Assert.assertNotNull(e4);
        } catch (InstantiationException | IllegalAccessException
                | IllegalArgumentException | InvocationTargetException
                | NoSuchMethodException | SecurityException e) {
            Assert.assertTrue(false);
        }
    }
}
