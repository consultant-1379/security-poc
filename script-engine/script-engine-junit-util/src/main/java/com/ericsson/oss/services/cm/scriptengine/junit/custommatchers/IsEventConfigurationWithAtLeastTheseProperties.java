package com.ericsson.oss.services.cm.scriptengine.junit.custommatchers;

import static org.mockito.Matchers.argThat;

import java.util.Map;

import org.mockito.ArgumentMatcher;

import com.ericsson.oss.itpf.sdk.eventbus.EventConfiguration;

/*
 *  This is the Slave copy, if updating this file you should also update the cm-common Master copy.
 *  The reason is to minimize complex dependency chains. Now script-engine does not depend on cm-common (duplication used instead)
 *  Please see TORF-112175 for more details.
 */
public class IsEventConfigurationWithAtLeastTheseProperties extends ArgumentMatcher<EventConfiguration> {
    private final Map<String, String> properties;

    public IsEventConfigurationWithAtLeastTheseProperties(final Map<String, String> properties) {
        this.properties = properties;
    }

    public static EventConfiguration isEventConfigurationWithAtLeastTheseProperties(final Map<String, String> properties) {
        return argThat(new IsEventConfigurationWithAtLeastTheseProperties(properties));
    }

    @Override
    public boolean matches(final Object object) {
        if (object instanceof EventConfiguration) {
            final EventConfiguration eventConfiguration = (EventConfiguration) object;
            for (final Map.Entry<String, String> keyValuePair : properties.entrySet()) {
                final String expectedKeyValuePairInToString = keyValuePair.getKey() + "=" + keyValuePair.getValue();
                if (!eventConfiguration.toString().contains(expectedKeyValuePairInToString)) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}
