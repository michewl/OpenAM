/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2021 Open Identity Platform Community.
 */
package com.sun.identity.saml2.plugins;

import com.sun.identity.plugin.datastore.DataStoreProviderException;
import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.plugin.session.SessionManager;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.shared.debug.DebugLevel;
import org.forgerock.openam.utils.CollectionUtils;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

import static org.forgerock.openam.utils.AttributeUtils.*;

/**
 * Adds the ability to provide an optional type argument for the mapped attributes.
 * <p>
 * The base functionality is implemented as in {@link DefaultLibraryIDPAttributeMapper}.
 * <p>
 * Supports attribute mappings in the following format:
 * <p><br/>
 * {@code [xsi:type|][NameFormatURI|]SAML ATTRIBUTE NAME=["]LOCAL NAME["][;binary]}
 * <p><br/>
 * Terminology
 * <dl>
 *     <dt><strong>local attribute</strong></dt>
 *     <dd>Describes the attribute as used in the datastore or session. Always the right side of the '{@code =}' in the
 *     attribute mapping configuration.</dd>
 *     <dt><strong>saml attribute</strong></dt>
 *     <dd>Describes the attribute name as used in SAML data. Always the left side of the '{@code =}' in the attribute
 *     mapping configuration.</dd>
 * </dl>
 *
 * @see DefaultLibraryIDPAttributeMapper
 */
public class TypedIDPAttributeMapper extends DefaultLibraryIDPAttributeMapper {

    @Override
    public List<Attribute> getAttributes(Object session, String hostEntityID, String remoteEntityID, String realm)
            throws SAML2Exception {

        final String loggingMethodName = "getAttributes";

        List<Attribute> attributes = new ArrayList<>();
        try {
            Objects.requireNonNull(session, bundle.getString("nullSSOToken"));
            Objects.requireNonNull(realm, bundle.getString("nullRealm"));
            Objects.requireNonNull(hostEntityID, bundle.getString("nullHostEntityID"));

            // Check for required session
            if (!SessionManager.getProvider().isValid(session)) {
                logDebugMessage(DebugLevel.MESSAGE, ".{}: Invalid session.", loggingMethodName);
                return attributes;
            }

            final Map<String, String> configuredMappings = getConfiguredMappings(hostEntityID, remoteEntityID, realm);

            // Get user values for configured mappings
            if (!configuredMappings.isEmpty()) {
                // The key is as in the mapping configuration but the values are resolved
                final Map<String, Set<String>> resolvedMappings = resolveLocalAttributeValues(session, realm, configuredMappings);
                if (!resolvedMappings.isEmpty()) {
                    attributes.addAll(getResolvedSamlAttributes(resolvedMappings, hostEntityID, remoteEntityID, realm));
                } else {
                    logDebugMessage(
                            DebugLevel.MESSAGE,
                            ".{}: No mapped attributes could be resolved.",
                            loggingMethodName
                    );
                }
            } else {
                logDebugMessage(
                        DebugLevel.MESSAGE,
                        ".{}: No configured attribute mappings found.",
                        loggingMethodName
                );
            }
        } catch (Exception e) {
            logDebugMessage(DebugLevel.ERROR, ".{}: Error while getting mapped attributes.", loggingMethodName, e);
            throw new SAML2Exception(e);
        }

        return attributes;
    }

    @Override
    protected boolean isIgnoredProfile(Object session, String realm) {
        return SAML2PluginsUtils.isIgnoredProfile(session, realm);
    }

    /**
     * Get the configured attribute mappings.
     * <p>
     * Will look up the configuration for the <strong>remote</strong> {@value SP} first and if not found tries to get it
     * for the <strong>hosted</strong> {@value IDP}.
     * <p>
     * Depending on the mapping configuration the saml attribute (key) can have the following form:
     * <p>
     * {@code [xsi:type|][NameFormatURI|]SAML ATTRIBUTE NAME}
     * <p><br/>
     * And the local attribute (value) can have the following form:
     * <p>
     * {@code ["]LOCAL NAME["][;binary]}
     *
     * @param hostEntityID   of the idp to lookup the attribute map configuration.
     * @param remoteEntityID of the sp to lookup the attribute map configuration.
     * @param realm          in which to look for the entities.
     * @return the attribute mappings or an empty map.
     * @throws SAML2Exception if the lookup fails.
     */
    @Nonnull
    private Map<String, String> getConfiguredMappings(@Nonnull String hostEntityID, @Nullable String remoteEntityID, @Nonnull String realm)
            throws SAML2Exception {

        final String loggingMethodName = "getConfiguredMappings";

        // Check SP
        if (remoteEntityID != null) {
            final Map<String, String> configuredRemoteSpMappings = getConfigAttributeMap(realm, remoteEntityID, SP);
            if (!CollectionUtils.isEmpty(configuredRemoteSpMappings)) {
                logDebugMessage(DebugLevel.MESSAGE, ".{}: SP mappings found.", loggingMethodName);
                logDebugMessage(DebugLevel.MESSAGE, ".{}: {}", loggingMethodName, configuredRemoteSpMappings);
                return configuredRemoteSpMappings;
            }
        } else {
            logDebugMessage(
                    DebugLevel.MESSAGE,
                    ".{}: Skipping config mapping lookup for '{}' since no remote entityId was provided.",
                    loggingMethodName,
                    SP
            );
        }

        // Check IdP
        final Map<String, String> configuredHostedIdpMappings = getConfigAttributeMap(realm, hostEntityID, IDP);
        if (!CollectionUtils.isEmpty(configuredHostedIdpMappings)) {
            logDebugMessage(DebugLevel.MESSAGE, ".{}: IdP mappings found.", loggingMethodName);
            logDebugMessage(DebugLevel.MESSAGE, ".{}: {}", loggingMethodName, configuredHostedIdpMappings);
            return configuredHostedIdpMappings;
        }

        logDebugMessage(DebugLevel.MESSAGE, ".{}: No attribute mappings found.", loggingMethodName);
        return new HashMap<>();
    }

    /**
     * Resolves the mapped local attribute values.
     * <p>
     * Resolves by
     * <ol>
     *     <li>using the static without any changes (except removing the {@value
     *     org.forgerock.openam.utils.AttributeUtils#STATIC_QUOTE})</li>
     *     <li>looking up the value in the {@link com.sun.identity.plugin.datastore.DataStoreProvider DataStoreProvider}
     *     (if not {@link DefaultLibraryIDPAttributeMapper#isIgnoredProfile(Object, String) isIgnoredProfile(Object, String)})</li>
     *     <li>looking up the value in the session properties</li>
     * </ol>
     * If configured mappings have no value through the above sources it will be dropped.
     *
     * @param session            to lookup the values if not static or in the datastore.
     * @param realm              to check in.
     * @param configuredMappings for the attributes.
     * @return the configured mapping with the local attribute values resolved.
     * @throws SessionException if the user session is invalid.
     */
    @Nonnull
    private Map<String, Set<String>> resolveLocalAttributeValues(
            @Nonnull Object session,
            @Nonnull String realm,
            @Nonnull Map<String, String> configuredMappings
    ) throws SessionException {

        final String loggingMethodName = "resolveLocalAttributeValues";

        final Map<String, Set<String>> resolvedMappings = new HashMap<>();
        for (Map.Entry<String, String> entry : configuredMappings.entrySet()) {
            // Set the value if static
            if (isStaticAttribute(entry.getValue())) {
                if (!isBinaryAttribute(entry.getValue())) {
                    logDebugMessage(
                            DebugLevel.WARNING,
                            ".{}: Static local attribute value can not be binary. Ignoring saml attribute '{}' mapped with local attribute '{}'.",
                            loggingMethodName,
                            entry.getKey(),
                            entry.getValue()
                    );
                    continue;
                }

                resolvedMappings.put(
                        entry.getKey(), CollectionUtils.asSet(removeStaticAttributeFlag(entry.getValue()))
                );
            } else {
                final Set<String> userDataValue = getLocalAttributeValueFromDatastoreOrSession(
                        session,
                        realm,
                        entry.getValue() != null ? entry.getValue() : ""
                );

                // No value found at all
                if (CollectionUtils.isEmpty(userDataValue)) {
                    logDebugMessage(
                            DebugLevel.MESSAGE,
                            ".{}: No user value found for saml attribute '{}' mapped with local attribute '{}'.",
                            loggingMethodName,
                            entry.getKey(),
                            entry.getValue()
                    );
                } else {
                    resolvedMappings.put(entry.getKey(), userDataValue);
                }
            }
        }

        return resolvedMappings;
    }

    /**
     * Tries to get the local attribute value from the datastore or the user session.
     *
     * @param session        to get the value from if not in the datastore.
     * @param realm          to check in.
     * @param localAttribute in the datastore or session.
     * @return the set of values for the local attribute or {@link null}.
     * @throws SessionException if the user session is invalid.
     */
    @Nullable
    private Set<String> getLocalAttributeValueFromDatastoreOrSession(
            @Nonnull Object session,
            @Nonnull String realm,
            @Nonnull String localAttribute
    ) throws SessionException {

        final String loggingMethodName = "getLocalAttributeValueFromDatastoreOrSession";

        Set<String> userDataValue = null;

        // Use DataStoreProvider to get the value if the user profile in authentication settings is not set to be ignored
        if (!isIgnoredProfile(session, realm)) {
            try {
                userDataValue = getDatastoreUserValue(session, localAttribute);
            } catch (DataStoreProviderException e) {
                logDebugMessage(
                        DebugLevel.WARNING,
                        ".{}: Error getting user values from datastore.",
                        loggingMethodName,
                        e
                );
                // This exception is only logged and does not break the processing
            }
        }

        // No value from DataStoreProvider so try the session
        if (CollectionUtils.isEmpty(userDataValue)) {
            // Check including binary flag
            logDebugMessage(
                    DebugLevel.MESSAGE,
                    ".{}: Getting session property for local attribute '{}'.",
                    loggingMethodName,
                    localAttribute
            );
            String[] sessionValues = SessionManager.getProvider().getProperty(session, localAttribute);
            if (sessionValues == null || sessionValues.length <= 0) {
                // No data found so try without binary flag
                logDebugMessage(
                        DebugLevel.MESSAGE,
                        ".{}: Getting session property for local attribute '{}'.",
                        loggingMethodName,
                        removeBinaryAttributeFlag(localAttribute)
                );
                sessionValues = SessionManager.getProvider().getProperty(session, removeBinaryAttributeFlag(localAttribute));
            }
            if (sessionValues != null) {
                userDataValue = CollectionUtils.asSet(sessionValues);
            }
        }

        logDebugMessage(
                DebugLevel.MESSAGE,
                ".{}: Got user value '{}' for local attribute '{}'",
                loggingMethodName,
                userDataValue,
                localAttribute
        );
        return userDataValue;
    }

    /**
     * Looks up the user values with the {@link com.sun.identity.plugin.datastore.DataStoreProvider} for a local
     * attribute.
     * <p>
     * Does support the binary flag.
     *
     * @param session        to get the user id from.
     * @param localAttribute which to get. This may still contain the binary flag ({@code ;binary}).
     * @return the set of values for the local attribute or {@code null}.
     * @throws SessionException           if the user session is invalid.
     * @throws DataStoreProviderException if the datastore can not be accessed.
     */
    @Nullable
    private Set<String> getDatastoreUserValue(@Nonnull Object session, @Nonnull String localAttribute)
            throws SessionException, DataStoreProviderException {

        final String loggingMethodName = "getDatastoreUserValue";

        logDebugMessage(
                DebugLevel.MESSAGE,
                ".{}: Getting datastore user value for local attribute '{}'.",
                loggingMethodName,
                localAttribute
        );

        if (isBinaryAttribute(localAttribute)) {
            byte[][] binaryAttributeData = dsProvider.getBinaryAttribute(
                    SessionManager.getProvider().getPrincipalName(session),
                    removeBinaryAttributeFlag(localAttribute)
            );

            if (binaryAttributeData != null && binaryAttributeData.length > 0) {
                Set<String> result = new HashSet<>();
                for (byte[] entry : binaryAttributeData) {
                    result.add(org.forgerock.util.encode.Base64.encode(entry));
                }
                return result;
            } else {
                logDebugMessage(
                        DebugLevel.WARNING,
                        ".{}: No binary data found for local attribute '{}'.",
                        loggingMethodName,
                        localAttribute
                );
                return null;
            }
        } else {
            return dsProvider.getAttribute(SessionManager.getProvider().getPrincipalName(session), localAttribute);
        }
    }

    /**
     * Resolves mappings to saml attributes.
     * <p>
     * Does not change local attribute values.
     * <p>
     * <strong>The key parsing is a very simplified and "dumb" implementation. Always assumes the NameFormatURI is
     * provided when a datatype is set.</strong>
     *
     * @param mappings with local attributes already resolved.
     * @return the list of saml attributes.
     */
    @Nonnull
    private List<Attribute> getResolvedSamlAttributes(
            @Nonnull Map<String, Set<String>> mappings,
            @Nonnull String hostEntityID,
            @Nullable String remoteEntityID,
            @Nonnull String realm
    ) throws SAML2Exception {

        final List<Attribute> attributes = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : mappings.entrySet()) {
            // Parse the key
            String name = null;
            String dataType = null;
            String nameFormatUri = null;

            final String[] keyParts = entry.getKey().split("\\|");
            // Looping from right to left
            for (int i = keyParts.length - 1; i >= 0; i--) {

                // Data type if third element (counted from right to left; zero index)
                if (i == keyParts.length - 3) {
                    dataType = keyParts[i];
                }

                // Name format if second element (counted from right to left; zero index)
                if (i == keyParts.length - 2) {
                    nameFormatUri = keyParts[i];
                }

                // Name if first element (counted from right to left; zero index)
                if (i == keyParts.length - 1) {
                    name = keyParts[i];
                }
            }

            Attribute samlAttribute = getSAMLAttribute(name, nameFormatUri, entry.getValue(), hostEntityID, remoteEntityID, realm);

            // Replace data type for attribute
            if (dataType != null) {
                final List<String> replacedAttributeValues = new ArrayList<>();
                for (Object value : samlAttribute.getAttributeValue()) {
                    // setAttributeValue() does some validation and requires the saml namespace on the element
                    // as it does not know it is already bound. In the original implementation this is worked
                    // around by only using setAttributeValueString() which hardcodes the type
                    replacedAttributeValues.add(
                            ((String) value).replace(
                                    "xsi:type=\"xs:string\"",
                                    "xsi:type=\"" + dataType + "\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
                            )
                    );
                }
                samlAttribute.setAttributeValue(replacedAttributeValues);
            }

            attributes.add(samlAttribute);
        }

        return attributes;
    }

    /**
     * Helper method to simplify logging.
     *
     * @param debugLevel      to write messages with.
     * @param messageTemplate the template for the messages.
     * @param params          the parameters for the message.
     * @see com.sun.identity.shared.debug.Debug
     */
    private void logDebugMessage(@Nonnull DebugLevel debugLevel, @Nonnull String messageTemplate, Object... params) {

        final String loggingMethodName = "logDebugMessage";

        String logPrefix = this.getClass().getSimpleName();
        if (!messageTemplate.startsWith(".")) logPrefix += ": ";

        switch (debugLevel) {
            case ERROR:
                if (debug.errorEnabled()) {
                    debug.error(logPrefix + messageTemplate, params);
                }
                break;
            case WARNING:
                if (debug.warningEnabled()) {
                    debug.warning(logPrefix + messageTemplate, params);
                }
                break;
            case MESSAGE:
                if (debug.messageEnabled()) {
                    debug.message(logPrefix + messageTemplate, params);
                }
                break;
            default:
                debug.warning(
                        this.getClass().getSimpleName()
                                + ".{}: Called with invalid DebugLevel of '{}'. Message will be logged with level 'ERROR'.",
                        loggingMethodName,
                        debugLevel.getName()
                );
                // Log the original message but with valid DebugLevel
                logDebugMessage(DebugLevel.ERROR, messageTemplate, params);
                break;
        }
    }
}
