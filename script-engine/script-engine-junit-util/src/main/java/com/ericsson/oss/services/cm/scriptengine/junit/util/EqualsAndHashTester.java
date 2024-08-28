package com.ericsson.oss.services.cm.scriptengine.junit.util;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import com.google.common.testing.EqualsTester;

/*
 *  This is the Slave copy, if updating this file you should also update the cm-common Master copy and the other slave copy in script-engine-editor-spi.
 *  The reason is to minimize complex dependency chains. Now script-engine does not depend on cm-common (duplication used instead)
 *  Please see TORF-112175 for more details.
 */
public class EqualsAndHashTester {

    /**
     * This method will automatically create copies with different values for all supported (primitive) types
     *
     * @param original
     * @param identicalInstance
     * @throws Exception
     */
    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    public void assertEqualsAndHashMethod(final Object original, final Object identicalInstance) throws Exception {
        assertEqualsAndHashMethod(original, identicalInstance, getModifiedCopies(original));
    }

    /**
     * This method will test equals and hasCode with provided differentObjects
     *
     * @param original
     * @param identicalInstance
     * @param differentObjects
     * @throws Exception
     */
    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    public void assertEqualsAndHashMethod(final Object original, final Object identicalInstance, final Object... differentObjects) throws Exception {
        //
        assertEqualsAndHashMethod(original, identicalInstance, Arrays.asList(differentObjects));
    }

    /**
     * This method will test equals and hasCode with provided differentObjects
     *
     * @param original
     * @param identicalInstance
     * @param differentObjects
     * @throws Exception
     */
    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    public void assertEqualsAndHashMethod(final Object original, final Object identicalInstance, final Collection<Object> differentObjects) throws Exception {
        final EqualsTester equalsTester = new EqualsTester();
        equalsTester.addEqualityGroup(original, identicalInstance);
        for (final Object object : differentObjects) {
            equalsTester.addEqualityGroup(object);
        }
        equalsTester.testEquals();
    }

    /*
     * P R I V A T E - M E T H O D S
     */

    @SuppressWarnings({"PMD.SignatureDeclareThrowsException", "PMD.AvoidThrowingRawExceptionTypes",
    "PMD.StdCyclomaticComplexity", "PMD.ModifiedCyclomaticComplexity"})
    private Collection<Object> getModifiedCopies(final Object original) throws Exception {
        final Collection<String> fieldsToChange = getFieldsICanChange(original);
        final Collection<Object> modifiedCopies = new ArrayList<>();
        for (final String changeFieldName : fieldsToChange) {
            try {
                final Object copyWith1ChangedField = original.getClass().newInstance();
                for (final Field field : original.getClass().getDeclaredFields()) {
                    if (!Modifier.isStatic(field.getModifiers())) {
                        field.setAccessible(true);
                        if (field.getName().equals(changeFieldName)) {
                            //TODO EEITSIK Add all numeric types
                            if (field.getGenericType().toString().equals("int")) {
                                field.set(copyWith1ChangedField, 1 + field.getInt(original));
                            }
                            if (field.getGenericType().toString().equals("long")) {
                                field.set(copyWith1ChangedField, 1l + field.getLong(original));
                            }
                            if (field.getGenericType().toString().equals("boolean")) {
                                field.set(copyWith1ChangedField, ! field.getBoolean(original));
                            }
                            if (field.getGenericType().toString().equals("class java.lang.String")) {
                                field.set(copyWith1ChangedField, "changed:" + String.valueOf(field.get(original)));
                            }
                            assertHashCode(original, changeFieldName, copyWith1ChangedField);
                            // TODO EEITSIK Throw exception advising the user to manually supply different objects for any other types
                            modifiedCopies.add(copyWith1ChangedField);
                        } else {
                            field.set(copyWith1ChangedField, field.get(original));
                        }
                    }
                }

            } catch (InstantiationException | IllegalAccessException e) {
                throw new RuntimeException("Cannot auto-generate different instances, provide them yourself or implement non-arguments constructor");
            }
        }
        return modifiedCopies;
    }

    @SuppressWarnings("PMD.AvoidThrowingRawExceptionTypes")
    private void assertHashCode(final Object original, final String changeFieldName, final Object copyWith1ChangedField) {
        if (original.hashCode()==copyWith1ChangedField.hashCode()) {
            throw new RuntimeException("hashcode() should be different when field '" + changeFieldName + "' value differs");
        }
    }

    private Collection<String> getFieldsICanChange(final Object original) {
        final Collection<String> typesICanChange = new HashSet<>();
        typesICanChange.add("int");
        typesICanChange.add("long");
        typesICanChange.add("boolean");
        typesICanChange.add("class java.lang.String");
        final Collection<String> fieldsToChange = new ArrayList<>();
        for (final Field field : original.getClass().getDeclaredFields()) {
            if (!Modifier.isStatic(field.getModifiers()) && !field.isAnnotationPresent(Deprecated.class)) {
                if (typesICanChange.contains(field.getGenericType().toString())) {
                    fieldsToChange.add(field.getName());
                }
            }
        }
        return fieldsToChange;
    }

}
