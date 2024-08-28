/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.test.util;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.*;

import org.junit.Assert;

public class EqualsAndHashTester {

    static final Map<Class<?>, Samples> TYPE_ARGUMENTS = new HashMap<Class<?>, Samples>();
    static final String ERROR_MESSAGE = " getter/setter failed test";

    private static final float FLOAT = 3.14159F;
    private static final double DOUBLE = 3.14159;
    private static final long LONG = 42L;
    private static final float FLOATALT = 3.14169F;
    private static final double DOUBLEALT = 3.14169;
    private static final long LONGALT = 43L;

    private static enum Mode {
        EQUAL, HASH, BOTH
    };

    static {
        final List<Object> obList = new ArrayList<Object>();
        obList.add(new Object());
        final Set<Object> obSet = new HashSet<Object>();
        obSet.add(new Object());
        final SortedSet<Object> obSortedSet = new TreeSet<Object>();
        obSortedSet.add("");
        final Map<Object, Object> obMap = new HashMap<Object, Object>();
        obMap.put(new Object(), new Object());
        final SortedMap<Comparable<?>, Object> obSortedMap = new TreeMap<Comparable<?>, Object>();
        obSortedMap.put("", new Object());
        TYPE_ARGUMENTS.put(Collection.class, new Samples(new ArrayList<Object>(), obList));
        TYPE_ARGUMENTS.put(List.class, new Samples(new ArrayList<Object>(), obList));
        TYPE_ARGUMENTS.put(Set.class, new Samples(new HashSet<Object>(), obSet));
        TYPE_ARGUMENTS.put(SortedSet.class, new Samples(new TreeSet<Object>(), obSortedSet));
        TYPE_ARGUMENTS.put(Map.class, new Samples(new HashMap<Object, Object>(), obMap));
        TYPE_ARGUMENTS.put(SortedMap.class, new Samples(new TreeMap<Comparable<?>, Object>(), obSortedMap));
        TYPE_ARGUMENTS.put(Boolean.class, new Samples(true, false));
        TYPE_ARGUMENTS.put(Boolean.TYPE, new Samples(true, false));
        TYPE_ARGUMENTS.put(Character.class, new Samples('Z', 'Y'));
        TYPE_ARGUMENTS.put(Character.TYPE, new Samples('Z', 'Y'));
        TYPE_ARGUMENTS.put(Byte.class, new Samples((byte) 42, (byte) 43));
        TYPE_ARGUMENTS.put(Byte.TYPE, new Samples((byte) 42, (byte) 43));
        TYPE_ARGUMENTS.put(Short.class, new Samples((short) 42, (short) 43));
        TYPE_ARGUMENTS.put(String.class, new Samples("StringA", "StringB"));
        TYPE_ARGUMENTS.put(Short.TYPE, new Samples((short) 42, (short) 43));
        TYPE_ARGUMENTS.put(Integer.class, new Samples(42, 43));
        TYPE_ARGUMENTS.put(Integer.TYPE, new Samples(42, 43));
        TYPE_ARGUMENTS.put(Long.class, new Samples(LONG, LONGALT));
        TYPE_ARGUMENTS.put(Long.TYPE, new Samples(LONG, LONGALT));
        TYPE_ARGUMENTS.put(Float.class, new Samples(FLOAT, FLOATALT));
        TYPE_ARGUMENTS.put(Float.TYPE, new Samples(FLOAT, FLOATALT));
        TYPE_ARGUMENTS.put(Double.class, new Samples(DOUBLE, DOUBLEALT));
        TYPE_ARGUMENTS.put(Double.TYPE, new Samples(DOUBLE, DOUBLEALT));
        TYPE_ARGUMENTS.put(BigDecimal.class, new Samples(new BigDecimal("3.14159"), new BigDecimal("3.14159")));
        TYPE_ARGUMENTS.put(BigInteger.class, new Samples(new BigInteger("12345678901234567890"), new BigInteger("12345678901234567891")));
        TYPE_ARGUMENTS.put(java.sql.Date.class, new Samples(new java.sql.Date(new Date().getTime()), new java.sql.Date((new Date().getTime()) + 1)));
        TYPE_ARGUMENTS.put(java.util.Date.class, new Samples(new java.sql.Date(new Date().getTime()), new java.sql.Date((new Date().getTime()) + 1)));
        TYPE_ARGUMENTS.put(Timestamp.class, new Samples(new Timestamp(new Date().getTime()), new Timestamp(new Date().getTime() + 1)));
    }

    private EqualsAndHashTester() {
    }

    public static void testEqualsAndHash(final Class<?> clazz) {
        testEqualsAndHash(Mode.BOTH, clazz, new ArrayList<String>());
    }

    public static void testEqualsAndHash(final Class<?> clazz, final String excludes) {
        testEqualsAndHash(Mode.BOTH, clazz, parseExcludes(excludes));
    }

    public static void testEquals(final Class<?> clazz) {
        testEqualsAndHash(Mode.EQUAL, clazz, new ArrayList<String>());
    }

    public static void testHash(final Class<?> clazz) {
        testEqualsAndHash(Mode.HASH, clazz, new ArrayList<String>());
    }

    public static void testEquals(final Class<?> clazz, final String excludes) {
        testEqualsAndHash(Mode.EQUAL, clazz, parseExcludes(excludes));
    }

    public static void testHash(final Class<?> clazz, final String excludes) {
        testEqualsAndHash(Mode.HASH, clazz, parseExcludes(excludes));
    }

    public static void testEqualsAndHash(final Mode mode, final Class<?> clazz, final List<String> excludes) {

        List<Field> fieldList = extractFieldList(clazz);
        fieldList = purgeFieldList(fieldList, excludes);
        try {
            final Object opA = clazz.newInstance();
            fillWithData(opA, fieldList);
            final Object opB = clazz.newInstance();
            fillWithData(opB, fieldList);
            if (!testEquality(opA, opB)) {
                Assert.fail("Equality test fail");
            }
            if (!testHashCode(opA, opB)) {
                Assert.fail("HashCode test fail");
            }
            final String result = testInequality(fieldList, opA, opB);
            if (result != "Success") {
                Assert.fail("Inequality test fail with error : " + result);
            }
        } catch (InstantiationException | IllegalAccessException e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    private static List<String> parseExcludes(final String excludes) {
        List<String> excludeFields;
        if (excludes != null) {
            excludeFields = Arrays.asList(excludes.split(","));
        } else {
            excludeFields = new ArrayList<String>();
        }
        return excludeFields;
    }

    private static String testInequality(final List<Field> fields, final Object opA, final Object opB) {
        String ret = "Success";
        for (final Field field : fields) {
            field.setAccessible(true);
            try {
                final Class<?> type = field.getType();
                if (TYPE_ARGUMENTS.containsKey(type)) {
                    final Object alt = TYPE_ARGUMENTS.get(type).getSampleB();
                    field.set(opB, alt);
                    final boolean result = testEquality(opA, opB);
                    if (result) {
                        ret = "Different " + field.getName() + " not affect equality";
                        return ret;
                    }
                    final boolean hashResult = testHashCode(opA, opB);
                    if (hashResult) {
                        ret = "Different " + field.getName() + " not affect hashCode";
                        return ret;
                    }
                    field.set(opB, TYPE_ARGUMENTS.get(type).getSampleA());
                }
            } catch (IllegalArgumentException | IllegalAccessException e) {
                e.printStackTrace();
                Assert.fail();
            }
        }
        return ret;
    }

    private static List<Field> purgeFieldList(final List<Field> fieldList, final List<String> excludeFields) {
        final List<Field> ret = new ArrayList<Field>();
        for (final Field field : fieldList) {
            if (excludeFields.contains(field.getName())) {
                continue;
            }
            final int modifiers = field.getModifiers();
            if ((modifiers & Modifier.FINAL) == Modifier.FINAL) {
                continue;
            }
            if ((modifiers & Modifier.STATIC) == Modifier.STATIC) {
                continue;
            }
            if ((modifiers & Modifier.TRANSIENT) == Modifier.TRANSIENT) {
                continue;
            }
            ret.add(field);
        }
        return ret;
    }

    private static boolean testEquality(final Object opA, final Object opB) {
        final boolean ret = opA.equals(opB);
        return ret;
    }

    private static boolean testHashCode(final Object opA, final Object opB) {
        final boolean ret = opA.hashCode() == opB.hashCode();
        return ret;
    }

    private static Object fillWithData(final Object op, final List<Field> fields) {
        for (final Field field : fields) {
            final Class<?> type = field.getType();
            field.setAccessible(true);
            try {
                if (TYPE_ARGUMENTS.containsKey(type)) {
                    field.set(op, TYPE_ARGUMENTS.get(type).getSampleA());
                } else {
                    field.set(op, null);
                }
            } catch (IllegalArgumentException | IllegalAccessException e) {
                e.printStackTrace();
                Assert.fail();
            }
        }
        return op;
    }

    private static List<Field> extractFieldList(final Class<?> clazz) {
        final List<Field> fields = Arrays.asList(clazz.getDeclaredFields());
        return fields;
    }
}
