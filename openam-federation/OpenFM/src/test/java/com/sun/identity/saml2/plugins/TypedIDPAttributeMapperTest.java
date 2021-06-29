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

import com.iplanet.sso.SSOToken;
import com.sun.identity.plugin.datastore.DataStoreProvider;
import com.sun.identity.plugin.datastore.DataStoreProviderException;
import com.sun.identity.plugin.session.SessionException;
import com.sun.identity.plugin.session.SessionManager;
import com.sun.identity.plugin.session.SessionProvider;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.common.SAML2Constants;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.common.SAML2Utils;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;
import static org.fest.assertions.Fail.fail;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

@PrepareForTest({SessionManager.class, SAML2Utils.class})
public class TypedIDPAttributeMapperTest extends PowerMockTestCase {

    /**
     * Name of the first saml attribute in the test data.
     * <p>
     * <code>[xsi:type|][NameFormatURI|]<strong><em>SAML ATTRIBUTE NAME</em></strong>=LOCAL NAME</code>
     */
    private static final String SAML_ATTRIBUTE_ONE_NAME = "samlAttributeOne";
    /**
     * Name of the second saml attribute in the test data.
     * <p>
     * <code>[xsi:type|][NameFormatURI|]<strong><em>SAML ATTRIBUTE NAME</em></strong>=LOCAL NAME</code>
     */
    private static final String SAML_ATTRIBUTE_TWO_NAME = "samlAttributeTwo";
    /**
     * Name of the third saml attribute in the test data.
     * <p>
     * <code>[xsi:type|][NameFormatURI|]<strong><em>SAML ATTRIBUTE NAME</em></strong>=LOCAL NAME</code>
     */
    private static final String SAML_ATTRIBUTE_THREE_NAME = "samlAttributeThree";
    /**
     * Local name of the first saml attribute in the test data.
     * <p>
     * <code>[xsi:type|][NameFormatURI|]SAML ATTRIBUTE NAME=<strong><em>LOCAL NAME</em></strong></code>
     */
    private static final String LOCAL_ATTRIBUTE_ONE_NAME = "LocalAttributeOne";
    /**
     * Local name of the second saml attribute in the test data.
     * <p>
     * <code>[xsi:type|][NameFormatURI|]SAML ATTRIBUTE NAME=<strong><em>LOCAL NAME</em></strong></code>
     */
    private static final String LOCAL_ATTRIBUTE_TWO_NAME = "LocalAttributeTwo";
    /**
     * Local name of the third saml attribute in the test data.
     * <p>
     * <code>[xsi:type|][NameFormatURI|]SAML ATTRIBUTE NAME=<strong><em>LOCAL NAME</em></strong></code>
     */
    private static final String LOCAL_ATTRIBUTE_THREE_NAME = "LocalAttributeThree";
    /**
     * The name format used in the test data.
     * <p>
     * <code>[xsi:type|][<strong><em>NameFormatURI</em></strong>|]SAML ATTRIBUTE NAME=LOCAL NAME</code>
     */
    private static final String NAME_FORMAT = "urn:oid:test:name:format";
    /**
     * The data type used in the test data.
     * <p>
     * <code>[<strong><em>xsi:type</em></strong>|][NameFormatURI|]SAML ATTRIBUTE NAME=LOCAL NAME</code>
     */
    private static final String DATA_TYPE = "xsd:string";

    /**
     * Mappings which configure the saml attribute name as key.
     * <p>
     * {@code SAML ATTRIBUTE NAME=LOCAL NAME}
     */
    private final Map<String, String> mappingSamlAttribute = new HashMap<>();
    /**
     * Mappings which configure the name format and saml attribute name as key.
     * <p>
     * {@code NameFormatURI|SAML ATTRIBUTE NAME=LOCAL NAME}
     */
    private final Map<String, String> mappingNameFormatSamlAttribute = new HashMap<>();
    /**
     * Mappings which configure the data type, name format and saml attribute name as key.
     * <p>
     * {@code xsi:type|NameFormatURI|SAML ATTRIBUTE NAME=LOCAL NAME}
     */
    private final Map<String, String> mappingDataTypeNameFormatSamlAttribute = new HashMap<>();
    private SSOToken ssoToken;
    private SessionProvider sessionProvider;
    private DataStoreProvider dataStoreProvider;

    @DataProvider(name = "mapping-variants")
    public Object[][] getMappingVariants() {

        return new Object[][]{
            {this.mappingSamlAttribute},
            {this.mappingNameFormatSamlAttribute},
            {this.mappingDataTypeNameFormatSamlAttribute}
        };
    }

    @DataProvider(name = "mapping-variants-with-type")
    public Object[][] getMappingVariantsWithType() {

        return new Object[][]{
            {this.mappingSamlAttribute, "saml-attribute"},
            {this.mappingNameFormatSamlAttribute, "name-format-saml-attribute"},
            {this.mappingDataTypeNameFormatSamlAttribute, "data-type-name-format-saml-attribute"}
        };
    }

    @BeforeMethod
    public void setUp() throws SessionException, SAML2Exception, DataStoreProviderException {
        ssoToken = mock(SSOToken.class);
        sessionProvider = mock(SessionProvider.class);
        dataStoreProvider = mock(DataStoreProvider.class);

        given(sessionProvider.isValid(ssoToken)).willReturn(true);

        PowerMockito.mockStatic(SessionManager.class);
        given(SessionManager.getProvider()).willReturn(sessionProvider);

        PowerMockito.mockStatic(SAML2Utils.class);
        given(SAML2Utils.getDataStoreProvider()).willReturn(dataStoreProvider);

        // Prepare different mappings
        initTestData();
    }

    @Test
    public void getAttributes_invalidSession_shouldReturnEmptyList() throws SAML2Exception, SessionException {

        given(sessionProvider.isValid(ssoToken)).willReturn(false);

        List<Attribute> attributes = new TypedIDPAttributeMapper().getAttributes(
            ssoToken,
            "test-host-entity-id",
            "test-remote-entity-id",
            "test-realm"
        );

        PowerMockito.verifyStatic(SessionManager.class);
        SessionManager.getProvider();

        assertThat(attributes).isEmpty();
    }

    @Test
    public void getAttributes_noConfiguredMappings_shouldReturnEmptyList() throws SAML2Exception {

        PowerMockito.mockStatic(SAML2Utils.class);
        given(SAML2Utils.getConfigAttributeMap(anyString(), anyString(), anyString()))
            .willReturn(new HashMap<String, String>());

        List<Attribute> attributes = new TypedIDPAttributeMapper().getAttributes(
            ssoToken,
            "test-host-entity-id",
            "test-remote-entity-id",
            "test-realm"
        );

        PowerMockito.verifyStatic(SAML2Utils.class, times(2));
        SAML2Utils.getConfigAttributeMap(anyString(), anyString(), anyString());

        assertThat(attributes).isEmpty();
    }

    @Test(dataProvider = "mapping-variants")
    public void getAttributes_spConfiguredMappings_shouldReturnMappings(Map<String, String> mappings)
        throws SAML2Exception, DataStoreProviderException {

        given(SAML2Utils.getConfigAttributeMap("test-realm", "test-remote-entity-id", SAML2Constants.SP_ROLE))
            .willReturn(mappings);
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_ONE_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_ONE_NAME + "Value"));
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_TWO_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_TWO_NAME + "Value"));
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_THREE_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_THREE_NAME + "Value"));

        List<Attribute> attributes = new TypedIDPAttributeMapper().getAttributes(
            ssoToken,
            "test-host-entity-id",
            "test-remote-entity-id",
            "test-realm"
        );

        PowerMockito.verifyStatic(SAML2Utils.class);
        SAML2Utils.getConfigAttributeMap("test-realm", "test-remote-entity-id", SAML2Constants.SP_ROLE);

        assertThat(attributes).isNotEmpty();
        assertThat(attributes.size()).isEqualTo(mappings.size());
    }

    @Test(dataProvider = "mapping-variants")
    public void getAttributes_idpConfiguredMappings_shouldReturnMappings(Map<String, String> mappings)
        throws SAML2Exception, DataStoreProviderException {

        given(SAML2Utils.getConfigAttributeMap("test-realm", "test-host-entity-id", SAML2Constants.IDP_ROLE))
            .willReturn(mappings);
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_ONE_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_ONE_NAME + "Value"));
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_TWO_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_TWO_NAME + "Value"));
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_THREE_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_THREE_NAME + "Value"));

        List<Attribute> attributes = new TypedIDPAttributeMapper().getAttributes(
            ssoToken,
            "test-host-entity-id",
            "test-remote-entity-id",
            "test-realm"
        );

        PowerMockito.verifyStatic(SAML2Utils.class);
        SAML2Utils.getConfigAttributeMap("test-realm", "test-remote-entity-id", SAML2Constants.SP_ROLE);
        PowerMockito.verifyStatic(SAML2Utils.class);
        SAML2Utils.getConfigAttributeMap("test-realm", "test-host-entity-id", SAML2Constants.IDP_ROLE);

        assertThat(attributes).isNotEmpty();
        assertThat(attributes.size()).isEqualTo(mappings.size());
    }

    @Test(dataProvider = "mapping-variants-with-type")
    public void getAttributes_shouldSetKeyDataProperly(Map<String, String> mappings, String mappingType)
        throws SAML2Exception, DataStoreProviderException {

        given(SAML2Utils.getConfigAttributeMap(anyString(), anyString(), anyString())).willReturn(mappings);
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_ONE_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_ONE_NAME + "Value"));
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_TWO_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_TWO_NAME + "Value"));
        given(dataStoreProvider.getAttribute(any(), eq(LOCAL_ATTRIBUTE_THREE_NAME)))
            .willReturn(Collections.singleton(LOCAL_ATTRIBUTE_THREE_NAME + "Value"));

        List<Attribute> attributes = new TypedIDPAttributeMapper().getAttributes(
            ssoToken,
            "test-host-entity-id",
            "test-remote-entity-id",
            "test-realm"
        );

        PowerMockito.verifyStatic(SAML2Utils.class);
        SAML2Utils.getConfigAttributeMap(anyString(), anyString(), anyString());

        assertThat(attributes).isNotEmpty();
        assertThat(attributes.size()).isEqualTo(mappings.size());
        assertAttributesByMappingKey(attributes, mappings, mappingType);
    }

    /**
     * Method to set test data mappings
     * <p>
     * <strong>Does not provide static or binary mapped values.</strong>
     */
    private void initTestData() {

        // Mappings which only have the saml attribute name as key
        this.mappingSamlAttribute.put(SAML_ATTRIBUTE_ONE_NAME, LOCAL_ATTRIBUTE_ONE_NAME);
        this.mappingSamlAttribute.put(SAML_ATTRIBUTE_TWO_NAME, LOCAL_ATTRIBUTE_TWO_NAME);
        this.mappingSamlAttribute.put(SAML_ATTRIBUTE_THREE_NAME, LOCAL_ATTRIBUTE_THREE_NAME);
        // Mappings which have the name format and the saml attribute name as key
        this.mappingNameFormatSamlAttribute.put(NAME_FORMAT + "|" + SAML_ATTRIBUTE_ONE_NAME, LOCAL_ATTRIBUTE_ONE_NAME);
        this.mappingNameFormatSamlAttribute.put(NAME_FORMAT + "|" + SAML_ATTRIBUTE_TWO_NAME, LOCAL_ATTRIBUTE_TWO_NAME);
        this.mappingNameFormatSamlAttribute.put(
            NAME_FORMAT + "|" + SAML_ATTRIBUTE_THREE_NAME, LOCAL_ATTRIBUTE_THREE_NAME
        );
        // Mappings which have the data type, name format and the saml attribute name as key
        this.mappingDataTypeNameFormatSamlAttribute.put(
            DATA_TYPE + "|" + NAME_FORMAT + "|" + SAML_ATTRIBUTE_ONE_NAME, LOCAL_ATTRIBUTE_ONE_NAME
        );
        this.mappingDataTypeNameFormatSamlAttribute.put(
            DATA_TYPE + "|" + NAME_FORMAT + "|" + SAML_ATTRIBUTE_TWO_NAME, LOCAL_ATTRIBUTE_TWO_NAME
        );
        this.mappingDataTypeNameFormatSamlAttribute.put(
            DATA_TYPE + "|" + NAME_FORMAT + "|" + SAML_ATTRIBUTE_THREE_NAME, LOCAL_ATTRIBUTE_THREE_NAME
        );
    }

    /**
     * Verifies that the mapping key is properly translated to the attribute metadata.
     *
     * @param attributes  that got returned.
     * @param mappings    the configured mappings.
     * @param mappingType which defines the values that are expected to be set.
     */
    @SuppressWarnings("unchecked")
    private void assertAttributesByMappingKey(
        List<Attribute> attributes,
        Map<String, String> mappings,
        String mappingType
    ) {

        switch (mappingType) {
            case "saml-attribute":
                for (Attribute attribute : attributes) {
                    assertThat(mappings.containsKey(attribute.getName())).isTrue();
                    assertThat(attribute.getNameFormat()).isNull();
                    assertThat(String.join("", attribute.getAttributeValueString()))
                        .isEqualTo(mappings.get(attribute.getName()) + "Value");
                    assertThat(String.join("", attribute.getAttributeValue()))
                        .contains("xsi:type=\"xs:string\"");
                }
                break;
            case "name-format-saml-attribute":
                for (Attribute attribute : attributes) {
                    assertThat(mappings.containsKey(NAME_FORMAT + "|" + attribute.getName())).isTrue();
                    assertThat(attribute.getNameFormat()).isEqualTo(NAME_FORMAT);
                    assertThat(String.join("", attribute.getAttributeValueString()))
                        .isEqualTo(mappings.get(NAME_FORMAT + "|" + attribute.getName()) + "Value");
                    assertThat(String.join("", attribute.getAttributeValue()))
                        .contains("xsi:type=\"xs:string\"");
                }
                break;
            case "data-type-name-format-saml-attribute":
                for (Attribute attribute : attributes) {
                    assertThat(mappings.containsKey(DATA_TYPE + "|" + NAME_FORMAT + "|" + attribute.getName())).isTrue();
                    assertThat(attribute.getNameFormat()).isEqualTo(NAME_FORMAT);
                    assertThat(String.join("", attribute.getAttributeValueString()))
                        .isEqualTo(mappings.get(DATA_TYPE + "|" + NAME_FORMAT + "|" + attribute.getName()) + "Value");
                    assertThat(String.join("", attribute.getAttributeValue()))
                        .contains("xsi:type=\"" + DATA_TYPE + "\"");
                }
                break;
            default:
                fail(String.format("Can not verify unknown mapping type '%s'", mappingType));
        }
    }
}
