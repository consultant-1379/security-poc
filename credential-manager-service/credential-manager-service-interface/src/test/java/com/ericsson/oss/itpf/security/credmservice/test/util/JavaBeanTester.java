/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.test.util;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Assert;

public class JavaBeanTester {

    static final Map<Class<?>, Object> TYPE_ARGUMENTS = new HashMap<Class<?>, Object>();
    static final Map<Class<?>, Method> TYPE_PRIMITIVE = new HashMap<Class<?>, Method>();
    static final String ERROR_MESSAGE = " getter/setter failed test";

    private static final float FLOAT = 3.14159F;
    private static final double DOUBLE = 3.14159;
    private static final long LONG = 42L;

    private static Logger log = Logger.getLogger(JavaBeanTester.class.getName());

    static {
        try {
            TYPE_PRIMITIVE.put(Boolean.TYPE, Assert.class.getMethod("assertEquals", String.class, Object.class, Object.class));
            TYPE_PRIMITIVE.put(Character.TYPE, Assert.class.getMethod("assertEquals", String.class, Long.TYPE, Long.TYPE));
            TYPE_PRIMITIVE.put(Byte.TYPE, Assert.class.getMethod("assertEquals", String.class, Long.TYPE, Long.TYPE));
            TYPE_PRIMITIVE.put(Short.TYPE, Assert.class.getMethod("assertEquals", String.class, Long.TYPE, Long.TYPE));
            TYPE_PRIMITIVE.put(Integer.TYPE, Assert.class.getMethod("assertEquals", String.class, Long.TYPE, Long.TYPE));
            TYPE_PRIMITIVE.put(Long.TYPE, Assert.class.getMethod("assertEquals", String.class, Long.TYPE, Long.TYPE));
            TYPE_PRIMITIVE.put(Float.TYPE, JavaBeanTester.class.getMethod("assertEquals", String.class, Float.TYPE, Float.TYPE));
            TYPE_PRIMITIVE.put(Double.TYPE, JavaBeanTester.class.getMethod("assertEquals", String.class, Double.TYPE, Double.TYPE));
        } catch (NoSuchMethodException | SecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    static {
        TYPE_ARGUMENTS.put(Collection.class, new ArrayList<Object>());
        TYPE_ARGUMENTS.put(List.class, new ArrayList<Object>());
        TYPE_ARGUMENTS.put(Set.class, new HashSet<Object>());
        TYPE_ARGUMENTS.put(SortedSet.class, new TreeSet<Object>());
        TYPE_ARGUMENTS.put(Map.class, new HashMap<Object, Object>());
        TYPE_ARGUMENTS.put(SortedMap.class, new TreeMap<Object, Object>());
        TYPE_ARGUMENTS.put(Boolean.class, true);
        TYPE_ARGUMENTS.put(Boolean.TYPE, true);
        TYPE_ARGUMENTS.put(Character.class, 'Z');
        TYPE_ARGUMENTS.put(Character.TYPE, 'Z');
        TYPE_ARGUMENTS.put(Byte.class, (byte) 42);
        TYPE_ARGUMENTS.put(Byte.TYPE, (byte) 42);
        TYPE_ARGUMENTS.put(Short.class, (short) 42);
        TYPE_ARGUMENTS.put(String.class, "String");
        TYPE_ARGUMENTS.put(Short.TYPE, (short) 42);
        TYPE_ARGUMENTS.put(Integer.class, 42);
        TYPE_ARGUMENTS.put(Integer.TYPE, 42);
        TYPE_ARGUMENTS.put(Long.class, LONG);
        TYPE_ARGUMENTS.put(Long.TYPE, LONG);
        TYPE_ARGUMENTS.put(Float.class, FLOAT);
        TYPE_ARGUMENTS.put(Float.TYPE, FLOAT);
        TYPE_ARGUMENTS.put(Double.class, DOUBLE);
        TYPE_ARGUMENTS.put(Double.TYPE, DOUBLE);
        TYPE_ARGUMENTS.put(BigDecimal.class, new BigDecimal("3.14159"));
        TYPE_ARGUMENTS.put(java.sql.Date.class, new java.sql.Date(new Date().getTime()));
        TYPE_ARGUMENTS.put(java.util.Date.class, new java.util.Date(new Date().getTime()));
        TYPE_ARGUMENTS.put(Timestamp.class, new Timestamp(new Date().getTime()));
        TYPE_ARGUMENTS.put(Calendar.class, Calendar.getInstance());
    }

    private JavaBeanTester() {

    }

    public static void assertEquals(final String msg, final float expected, final float actual) {
        Assert.assertEquals(msg, expected, actual, 0);
    }

    public static void assertEquals(final String msg, final double expected, final double actual) {
        Assert.assertEquals(msg, expected, actual, 0);
    }

    static final Map<Class<?>, Object> DEFAULT_TYPE_ARGUMENTS = Collections.unmodifiableMap(new HashMap<Class<?>, Object>(TYPE_ARGUMENTS));

    public static void assertBasicGetterSetterBehavior(final Object target, final String property) {

        try {
            final PropertyDescriptor descriptor = new PropertyDescriptor(property, target.getClass());

            Object arg = null;
            final Class<?> type = descriptor.getPropertyType();
            if (TYPE_ARGUMENTS.containsKey(type)) {
                arg = TYPE_ARGUMENTS.get(type);
            } else {
                // TODO
                // arg = ReflectionUtils
                // .invokeDefaultConstructorEvenIfPrivate(type);
            }
            final Method writeMethod = descriptor.getWriteMethod();
            final Method readMethod = descriptor.getReadMethod();

            writeMethod.invoke(target, arg);
            final Object propertyValue = readMethod.invoke(target);
            if (TYPE_PRIMITIVE.containsKey(type)) {
                final Method method = TYPE_PRIMITIVE.get(type);
                method.invoke(null, ERROR_MESSAGE, arg, propertyValue);
            } else {
                assertSame(property + " getter/setter failed test", arg, propertyValue);
            }
        } catch (final IntrospectionException e) {
            final String msg = "Error creating PropertyDescriptor for property [" + property + "]. Do you have a getter and a setter?";
            log.log(Level.SEVERE, msg, e);
            fail(msg);
        } catch (final IllegalAccessException e) {
            final String msg = "Error accessing property. Are the getter and setter both accessible?";
            log.log(Level.SEVERE, msg, e);
            fail(msg);
        } catch (final InvocationTargetException e) {
            final String msg = "Error invoking method on target";
            fail(msg);
            log.log(Level.SEVERE, msg, e);
        }
    }

    public static void assertBasicGetterSetterBehavior(final Object target) {
        try {
            final BeanInfo beanInfo = Introspector.getBeanInfo(target.getClass());
            final PropertyDescriptor[] descriptors = beanInfo.getPropertyDescriptors();
            for (final PropertyDescriptor descriptor : descriptors) {
                if (descriptor.getWriteMethod() == null) {
                    continue;
                }
                if (descriptor.getPropertyType().isArray()) {
                    continue;
                }
                assertBasicGetterSetterBehavior(target, descriptor.getDisplayName());
            }
        } catch (final IntrospectionException e) {
            fail("Failed while introspecting target " + target.getClass());
        }
    }

    public static void assertBasicGetterSetterAndToStringBehavior(final Object target) {
        assertBasicGetterSetterBehavior(target);
        Assert.assertTrue(String.class == target.toString().getClass());
    }
}
