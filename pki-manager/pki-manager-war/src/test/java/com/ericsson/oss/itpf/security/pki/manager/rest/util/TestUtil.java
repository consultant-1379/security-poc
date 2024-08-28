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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

import org.json.JSONArray;
import org.json.JSONObject;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.AttributeType;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * A utility class to be used by test classes.
 * 
 * @author xhemgan
 * @version 1.1.30
 */
public class TestUtil {

    /**
     * places the given attribute in the first row in the JSON array.
     * 
     * @param jsonArray
     *            JSON array which has to be sorted.
     * @param attributeType
     *            type of the attribute based on which the array has to be sorted.
     * @param attributeValue
     *            value of the attribute which has to be placed in the first row.
     * @return a sorted JSON array.
     * 
     */
    public String placeAttributeAtFirst(final JSONArray jsonArray, final AttributeType attributeType, final String attributeValue) {

        final JSONArray sortedArray = new JSONArray();

        for (int i = 0; i < jsonArray.length(); i++) {

            final JSONObject jsonObject = jsonArray.getJSONObject(i);

            if (jsonObject.get(attributeType.getValue()).toString().equals(attributeValue)) {
                jsonArray.remove(i);
                sortedArray.put(0, jsonObject);
            }
        }

        return mergeJsonArray(sortedArray, jsonArray).toString();
    }

    /**
     * merges the input JSON arrays into one.
     * 
     * @param jsonArrays
     *            one or more JSON arrays that should be merged.
     * @return the merged JSON array.
     */
    public JSONArray mergeJsonArray(final JSONArray... jsonArrays) {

        final JSONArray mergedJsonArray = new JSONArray();

        for (final JSONArray jsonArray : jsonArrays) {
            for (int i = 0; i < jsonArray.length(); i++) {
                mergedJsonArray.put(jsonArray.getJSONObject(i));
            }
        }

        return mergedJsonArray;
    }

    /**
     * updates the profileType in the given JSON arryy from enum to its value.
     * 
     * @param jsonArray
     *            a JSON array which has to be updated.
     * @return the updated JSON array.
     */
    public JSONArray updateProfileTypeWithValue(final JSONArray jsonArray) {

        for (int i = 0; i < jsonArray.length(); i++) {
            final JSONObject jsonObject = jsonArray.getJSONObject(i);
            final String profileType = jsonObject.getString("type");
            final ProfileType profileTypeEnum = ProfileType.valueOf(profileType);
            jsonObject.put("profileType", profileTypeEnum.getValue());
            jsonArray.put(i, jsonObject);
        }

        return jsonArray;
    }

    /**
     * Converts the values of enum into a JSON string.
     * 
     * @param enumClass
     *            class of enum whose values should be converted to JSON
     * @param enumSerializer
     *            an instance of JSON serializer for the given enum
     * @param values
     *            and array of values of enum
     * @return a JSON string of the values in a given enum
     * 
     * @throws JsonProcessingException
     */
    public <T> String getJsonForEnum(final Class<? extends T> enumClass, final JsonSerializer<T> enumSerializer, final T[] values) throws JsonProcessingException {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(enumClass, enumSerializer);

        mapper.registerModule(module);

        final String result = mapper.writeValueAsString(values);

        return result;
    }
}
