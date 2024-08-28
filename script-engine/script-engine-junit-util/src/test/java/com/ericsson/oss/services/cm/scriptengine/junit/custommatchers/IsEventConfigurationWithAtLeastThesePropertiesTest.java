package com.ericsson.oss.services.cm.scriptengine.junit.custommatchers;

import static com.ericsson.oss.services.cm.scriptengine.junit.custommatchers.IsEventConfigurationWithAtLeastTheseProperties.isEventConfigurationWithAtLeastTheseProperties;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.ericsson.oss.itpf.sdk.eventbus.EventConfiguration;
import com.ericsson.oss.itpf.sdk.eventbus.EventConfigurationBuilder;

/*
 *  This is the Slave copy, if updating this file you should also update the cm-common Master copy.
 *  The reason is to minimize complex dependency chains. Now script-engine does not depend on cm-common (duplication used instead)
 *  Please see TORF-112175 for more details.
 */
public class IsEventConfigurationWithAtLeastThesePropertiesTest {

    final Map<String, String> expectedProperties = new HashMap<>();
    IsEventConfigurationWithAtLeastTheseProperties objUnderTest;
    EventConfiguration eventConfiguration = null;
    String eventPropertyName = "somePropertyName";
    String eventPropertyValue = "some property value";

    @Test
    public void matches_withOtherTypeOfObject_retrunsFalse() {
        final Object object = "some String";
        objUnderTest = new IsEventConfigurationWithAtLeastTheseProperties(null);
        assertFalse(objUnderTest.matches(object));
    }

    @Test
    public void matches_withNull_retrunsFalse() {
        objUnderTest = new IsEventConfigurationWithAtLeastTheseProperties(null);
        assertFalse(objUnderTest.matches(eventConfiguration));
    }

    @Test
    public void matches_withEventConfigurationWithoutProperties_withEmtpyProperties_retrunsTrue() {
        eventConfiguration = new EventConfigurationBuilder().build();
        objUnderTest = new IsEventConfigurationWithAtLeastTheseProperties(expectedProperties);
        assertTrue(objUnderTest.matches(eventConfiguration));
    }

    @Test
    public void matches_withEventConfigurationWithProperties_withSameProperties_retrunsTrue() {
        createEventConfigurationWithSomeProperties();
        expectedProperties.put(eventPropertyName, eventPropertyValue);
        objUnderTest = new IsEventConfigurationWithAtLeastTheseProperties(expectedProperties);
        assertTrue(objUnderTest.matches(eventConfiguration));
    }

    @Test
    public void matches_withEventConfigurationWithProperties_withOtherProperties_retrunsFalse() {
        eventConfiguration = new EventConfigurationBuilder().addEventProperty(eventPropertyName, "other value").build();
        expectedProperties.put(eventPropertyName, eventPropertyValue);
        objUnderTest = new IsEventConfigurationWithAtLeastTheseProperties(expectedProperties);
        assertFalse(objUnderTest.matches(eventConfiguration));
    }

    @Test
    public void isEventConfigurationWithAtLeastTheseProperties_withExpectedProperties_usedInWhen_resultsIncorrectMockedBehavior() {
        final IsEventConfigurationWithAtLeastThesePropertiesTest mockForTest = mock(IsEventConfigurationWithAtLeastThesePropertiesTest.class);
        expectedProperties.put(eventPropertyName, eventPropertyValue);
        final String resultFromMock = "Result from mock";
        when(mockForTest.dummyMethod(isEventConfigurationWithAtLeastTheseProperties(expectedProperties))).thenReturn(resultFromMock);
        createEventConfigurationWithSomeProperties();
        assertEquals(resultFromMock, mockForTest.dummyMethod(eventConfiguration));
    }

    @Test
    public void isEventConfigurationWithAtLeastTheseProperties_withOtherProperties_usedInWhen_resultsInNull() {
        final IsEventConfigurationWithAtLeastThesePropertiesTest mockForTest = mock(IsEventConfigurationWithAtLeastThesePropertiesTest.class);
        final Map<String, String> otherProperties = new HashMap<>();
        otherProperties.put("other key", "other value");
        expectedProperties.put(eventPropertyName, eventPropertyValue);
        when(mockForTest.dummyMethod(isEventConfigurationWithAtLeastTheseProperties(otherProperties))).thenReturn("Result from mock");
        createEventConfigurationWithSomeProperties();
        assertNull(mockForTest.dummyMethod(eventConfiguration));
    }

    private void createEventConfigurationWithSomeProperties() {
        eventConfiguration = new EventConfigurationBuilder().addEventProperty(eventPropertyName, eventPropertyValue).build();
    }

    String dummyMethod(final EventConfiguration eventConfiguration) {
        return "Result from real method";
    }

}
