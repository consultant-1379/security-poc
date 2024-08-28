package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.util.Set;
import java.util.TreeSet;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanServerConnection;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.QueryExp;
import javax.management.ReflectionException;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.SystemManagementException;

@PrepareForTest({SystemManagement.class, JMXConnectorFactory.class})
@RunWith(PowerMockRunner.class)
@PowerMockIgnore("org.apache.logging.log4j.*")
public class SystemManagementTest {

    @Test
    public void testPrivateConstructorSysMng() throws NoSuchMethodException, SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Constructor<SystemManagement> constructor;
        constructor = SystemManagement.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        SystemManagement sysMng = constructor.newInstance();
        assertTrue(sysMng != null);
    }
    
    @Test
    public void testRestartHttpConnectorPort() throws Exception {
        PowerMockito.whenNew(JMXServiceURL.class).withArguments("service:jmx:remoting-jmx://localhost:9999").thenThrow(new MalformedURLException());
        try {
            SystemManagement.restartHttpConnector(0);
            assertTrue(false);
        } catch (SystemManagementException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testRestartHttpConnectorPortOffset() {
        try {
            SystemManagement.restartHttpConnector(0,20);
            assertTrue(false);
        } catch (SystemManagementException e) {
            assertTrue(true); //MalformedUrl on connect, which extends IOexception
        }
    }
    
    @Test
    public void testRestartHttpConnectorAllPar() throws IOException, MalformedObjectNameException, InstanceNotFoundException, MBeanException, ReflectionException {
        PowerMockito.mockStatic(JMXConnectorFactory.class);
        JMXServiceURL mockjmxUrl = new JMXServiceURL("service:jmx:remoting-jmx://fakeHost:20");        
        JMXConnector mockjmxConn = PowerMockito.mock(JMXConnector.class);
        MBeanServerConnection mockMbeanServConn = PowerMockito.mock(MBeanServerConnection.class);
        
        PowerMockito.when(JMXConnectorFactory.connect(mockjmxUrl, null)).thenReturn(mockjmxConn);
        PowerMockito.when(mockjmxConn.getMBeanServerConnection()).thenReturn(mockMbeanServConn);
        
        ObjectName objNameEntry1 = new ObjectName("test.domain","port","0");
        ObjectName objNameEntry2 = new ObjectName("test.domain","fakeKey","fakeValue");
        Set<ObjectName> objNameSet = new TreeSet<ObjectName>();
        objNameSet.add(objNameEntry1);
        objNameSet.add(objNameEntry2);
        PowerMockito.when(mockMbeanServConn.queryNames(Matchers.any(ObjectName.class), Matchers.any(QueryExp.class))).thenReturn(objNameSet);
        PowerMockito.when(mockMbeanServConn.invoke(Matchers.eq(objNameEntry1), Matchers.anyString(), Matchers.any(Object[].class), Matchers.any(String[].class))).thenReturn(null);
        try {
            SystemManagement.restartHttpConnector(0,"fakeHost",20);
            assertTrue(true);
        } catch (SystemManagementException e) {
            assertTrue(false);
        }
        
        //Exceptions
        Exception exc = new Exception();
        PowerMockito.when(mockMbeanServConn.invoke(Matchers.eq(objNameEntry1),
                Matchers.anyString(), Matchers.any(Object[].class), Matchers.any(String[].class)))
                .thenThrow(new InstanceNotFoundException())
                .thenThrow(new MBeanException(exc))
                .thenThrow(new ReflectionException(exc));
        for(int i=0; i<3; i++) {
            try {
                SystemManagement.restartHttpConnector(0,"fakeHost",20);
                assertTrue(false);
            } catch (SystemManagementException e) {
                assertTrue(true);
            }
        }

    }
}
