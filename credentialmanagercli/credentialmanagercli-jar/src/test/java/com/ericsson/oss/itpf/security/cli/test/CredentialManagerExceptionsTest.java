package com.ericsson.oss.itpf.security.cli.test;

import java.lang.reflect.InvocationTargetException;

import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CredentialManagerExceptionsTest {

    
    @Test
    public void exceptionsTest() {
        this.exceptionClassTest(CredentialManagerException.class);
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
            T e5 = tex.getDeclaredConstructor(String.class, Throwable.class, boolean.class, boolean.class).newInstance("msg",e1,false,true);
            Assert.assertNotNull(e5);
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException |
                InvocationTargetException | NoSuchMethodException | SecurityException e) {
            Assert.assertTrue(false);
        }

    }
    
}
