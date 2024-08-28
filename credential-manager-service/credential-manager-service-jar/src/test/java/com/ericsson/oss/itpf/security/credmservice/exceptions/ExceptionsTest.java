package com.ericsson.oss.itpf.security.credmservice.exceptions;

import java.lang.reflect.InvocationTargetException;

import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;

public class ExceptionsTest {

    @Test
    public void exceptionsTest() {
        
        this.exceptionClassTest(CredentialManagerEntitiesException.class);
        this.exceptionClassTest(CredentialManagerProfilesException.class);
        this.exceptionClassTest(CredentialManagerCategoriesException.class);
        this.exceptionClassTest(CredentialManagerCheckException.class);
        this.exceptionClassTest(CredentialManagerStartupException.class);
        this.exceptionClassTest(CredentialManagerStorageException.class);
        this.exceptionClassTest(PkiCategoryMapperException.class);
        this.exceptionClassTest(PkiEntityMapperException.class);
        this.exceptionClassTest(PkiProfileMapperException.class);
        this.exceptionClassTest(CredentialManagerDbUpgradeException.class);
        
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
        } catch ( InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException | 
                NoSuchMethodException | SecurityException e) {
            Assert.assertTrue(false);
        }
        
    }

}
