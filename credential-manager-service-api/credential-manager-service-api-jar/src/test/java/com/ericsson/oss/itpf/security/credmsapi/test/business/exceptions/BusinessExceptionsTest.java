package com.ericsson.oss.itpf.security.credmsapi.test.business.exceptions;

import java.lang.reflect.InvocationTargetException;

import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.CertHandlerException;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.SystemManagementException;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.TrustHandlerException;

public class BusinessExceptionsTest {
    @Test
    public void ExceptionsTest() {
        this.exceptionClassTest(CertHandlerException.class);
        
        this.exceptionClassTest(SystemManagementException.class);

        this.exceptionClassTest(TrustHandlerException.class);

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
