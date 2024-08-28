/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.service.resource.listener;

import java.lang.reflect.Field;

/**
 * 
 * @author xbensar
 *
 */
public class ReflectionTestUtils {

    /**
     * This method is used to get the all the fields of the given class.
     * 
     * @param classToSearch
     *            the class for which the fields need to be found
     * @param fieldType
     *            the fieldType which has to be searched
     * @return the array of fields which are present in the class
     * @throws SecurityException
     *             thrown when the fields of the given class are not accessible
     */
    public static Field[] getFields(final Class<?> classToSearch, final Class<?> fieldType) throws SecurityException {
        if (fieldType == null) {
            throw new IllegalArgumentException("The fieldType Class must not be null");
        }

        final Field[] fields = classToSearch.getDeclaredFields();
        if (fields.length == 0) {
            throw new IllegalArgumentException("The Class " + classToSearch.getName() + "must contain fields");
        }
        return fields;
    }

    /**
     * This method sets the field represented by this Field object on the specified object argument to the specified new value.
     * 
     * @param classToSearch
     *            the class for which the declared fields have to be found
     * @param fieldType
     *            the field type for which the value needs to set for the classToSearch instance
     * @param fieldName
     *            the name of the field variable whose value has to be reset.
     * @param classInstance
     *            the instance of classToSearch 
     * @param value
     *            the field whose value has to be set for the classInstance
     * @throws SecurityException
     *             thrown when the fields of the given class are not accessible
     * @throws IllegalAccessException
     *             thrown when the Field object is enforcing Java language access control and the underlying field is either inaccessible or final
     */
    public static void setPrimitiveField(final Class<?> classToSearch, final Class<?> fieldType, final String fieldName, final Object classInstance, final Object value) throws SecurityException,
            IllegalAccessException {

        for (final Field field : getFields(classToSearch, fieldType)) {
            field.setAccessible(true);
            if (field.getName().equalsIgnoreCase(fieldName)) {
                field.set(classInstance, value);
                return;
            }
        }
        throw new IllegalArgumentException("The field name " + fieldName + "was not found");
    }
}
