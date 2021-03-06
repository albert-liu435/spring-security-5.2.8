/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configurers;

import com.google.common.net.HttpHeaders;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Tests for {@link HeadersConfigurer}.
 *
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Joe Grandja
 * @author Edd?? Mel??ndez
 * @author Vedran Pavic
 * @author Eleftheria Stein
 */
public class HeadersConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void getWhenHeadersConfiguredThenDefaultHeadersInResponse() throws Exception {
		this.spring.register(HeadersConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.DENY.name()))
				.andExpect(header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "1; mode=block"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(
				HttpHeaders.X_CONTENT_TYPE_OPTIONS, HttpHeaders.X_FRAME_OPTIONS, HttpHeaders.STRICT_TRANSPORT_SECURITY,
				HttpHeaders.CACHE_CONTROL, HttpHeaders.EXPIRES, HttpHeaders.PRAGMA, HttpHeaders.X_XSS_PROTECTION);
	}

	@EnableWebSecurity
	static class HeadersConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers();
			// @formatter:on
		}
	}

	@Test
	public void getWhenHeadersConfiguredInLambdaThenDefaultHeadersInResponse() throws Exception {
		this.spring.register(HeadersInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.DENY.name()))
				.andExpect(header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "1; mode=block"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(
				HttpHeaders.X_CONTENT_TYPE_OPTIONS, HttpHeaders.X_FRAME_OPTIONS, HttpHeaders.STRICT_TRANSPORT_SECURITY,
				HttpHeaders.CACHE_CONTROL, HttpHeaders.EXPIRES, HttpHeaders.PRAGMA, HttpHeaders.X_XSS_PROTECTION);
	}

	@EnableWebSecurity
	static class HeadersInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(withDefaults());
			// @formatter:on
		}
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndContentTypeConfiguredThenOnlyContentTypeHeaderInResponse()
			throws Exception {
		this.spring.register(ContentTypeOptionsConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_CONTENT_TYPE_OPTIONS);
	}

	@EnableWebSecurity
	static class ContentTypeOptionsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentTypeOptions();
			// @formatter:on
		}
	}

	@Test
	public void getWhenOnlyContentTypeConfiguredInLambdaThenOnlyContentTypeHeaderInResponse()
			throws Exception {
		this.spring.register(ContentTypeOptionsInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_CONTENT_TYPE_OPTIONS);
	}

	@EnableWebSecurity
	static class ContentTypeOptionsInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.contentTypeOptions(withDefaults())
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndFrameOptionsConfiguredThenOnlyFrameOptionsHeaderInResponse()
			throws Exception {
		this.spring.register(FrameOptionsConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.DENY.name()))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_FRAME_OPTIONS);
	}

	@EnableWebSecurity
	static class FrameOptionsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.frameOptions();
			// @formatter:on
		}
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndHstsConfiguredThenOnlyStrictTransportSecurityHeaderInResponse()
			throws Exception {
		this.spring.register(HstsConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.STRICT_TRANSPORT_SECURITY);
	}

	@EnableWebSecurity
	static class HstsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpStrictTransportSecurity();
			// @formatter:on
		}
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndCacheControlConfiguredThenCacheControlAndExpiresAndPragmaHeadersInResponse()
			throws Exception {
		this.spring.register(CacheControlConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(HttpHeaders.CACHE_CONTROL,
				HttpHeaders.EXPIRES, HttpHeaders.PRAGMA);
	}

	@EnableWebSecurity
	static class CacheControlConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.cacheControl();
			// @formatter:on
		}
	}

	@Test
	public void getWhenOnlyCacheControlConfiguredInLambdaThenCacheControlAndExpiresAndPragmaHeadersInResponse()
			throws Exception {
		this.spring.register(CacheControlInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(HttpHeaders.CACHE_CONTROL,
				HttpHeaders.EXPIRES, HttpHeaders.PRAGMA);
	}

	@EnableWebSecurity
	static class CacheControlInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.cacheControl(withDefaults())
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndXssProtectionConfiguredThenOnlyXssProtectionHeaderInResponse()
			throws Exception {
		this.spring.register(XssProtectionConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "1; mode=block"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_XSS_PROTECTION);
	}

	@EnableWebSecurity
	static class XssProtectionConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.xssProtection();
			// @formatter:on
		}
	}

	@Test
	public void getWhenOnlyXssProtectionConfiguredInLambdaThenOnlyXssProtectionHeaderInResponse()
			throws Exception {
		this.spring.register(XssProtectionInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "1; mode=block"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.X_XSS_PROTECTION);
	}

	@EnableWebSecurity
	static class XssProtectionInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.xssProtection(withDefaults())
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenFrameOptionsSameOriginConfiguredThenFrameOptionsHeaderHasValueSameOrigin() throws Exception {
		this.spring.register(HeadersCustomSameOriginConfig.class).autowire();

		this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.SAMEORIGIN.name()))
				.andReturn();
	}

	@EnableWebSecurity
	static class HeadersCustomSameOriginConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.frameOptions().sameOrigin();
			// @formatter:on
		}
	}

	@Test
	public void getWhenFrameOptionsSameOriginConfiguredInLambdaThenFrameOptionsHeaderHasValueSameOrigin()
			throws Exception {
		this.spring.register(HeadersCustomSameOriginInLambdaConfig.class).autowire();

		this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS, XFrameOptionsMode.SAMEORIGIN.name()))
				.andReturn();
	}

	@EnableWebSecurity
	static class HeadersCustomSameOriginInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin())
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHeaderDefaultsDisabledAndPublicHpkpWithNoPinThenNoHeadersInResponse() throws Exception {
		this.spring.register(HpkpConfigNoPins.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).isEmpty();
	}

	@EnableWebSecurity
	static class HpkpConfigNoPins extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning();
			// @formatter:on
		}
	}

	@Test
	public void getWhenSecureRequestAndHpkpWithPinThenPublicKeyPinsReportOnlyHeaderInResponse()
			throws Exception {
		this.spring.register(HpkpConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@Test
	public void getWhenInsecureRequestHeaderDefaultsDisabledAndHpkpWithPinThenNoHeadersInResponse()
			throws Exception {
		this.spring.register(HpkpConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).isEmpty();
	}

	@EnableWebSecurity
	static class HpkpConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=");
			// @formatter:on
		}
	}

	@Test
	public void getWhenHpkpWithMultiplePinsThenPublicKeyPinsReportOnlyHeaderWithMultiplePinsInResponse()
			throws Exception {
		this.spring.register(HpkpConfigWithPins.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\""))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class HpkpConfigWithPins extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			Map<String, String> pins = new LinkedHashMap<>();
			pins.put("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256");
			pins.put("E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=", "sha256");

			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.withPins(pins);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHpkpWithCustomAgeThenPublicKeyPinsReportOnlyHeaderWithCustomAgeInResponse() throws Exception {
		this.spring.register(HpkpConfigCustomAge.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
						"max-age=604800 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class HpkpConfigCustomAge extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.maxAgeInSeconds(604800);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHpkpWithReportOnlyFalseThenPublicKeyPinsHeaderInResponse() throws Exception {
		this.spring.register(HpkpConfigTerminateConnection.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS,
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\""))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS);
	}

	@EnableWebSecurity
	static class HpkpConfigTerminateConnection extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.reportOnly(false);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHpkpIncludeSubdomainThenPublicKeyPinsReportOnlyHeaderWithIncludeSubDomainsInResponse()
			throws Exception {
		this.spring.register(HpkpConfigIncludeSubDomains.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; includeSubDomains"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class HpkpConfigIncludeSubDomains extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.includeSubDomains(true);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHpkpWithReportUriThenPublicKeyPinsReportOnlyHeaderWithReportUriInResponse() throws Exception {
		this.spring.register(HpkpConfigWithReportURI.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\""))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class HpkpConfigWithReportURI extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.reportUri(new URI("https://example.net/pkp-report"));
			// @formatter:on
		}
	}

	@Test
	public void getWhenHpkpWithReportUriAsStringThenPublicKeyPinsReportOnlyHeaderWithReportUriInResponse()
			throws Exception {
		this.spring.register(HpkpConfigWithReportURIAsString.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\""))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class HpkpConfigWithReportURIAsString extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpPublicKeyPinning()
						.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
						.reportUri("https://example.net/pkp-report");
			// @formatter:on
		}
	}

	@Test
	public void getWhenHpkpWithReportUriInLambdaThenPublicKeyPinsReportOnlyHeaderWithReportUriInResponse()
			throws Exception {
		this.spring.register(HpkpWithReportUriInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY,
						"max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.net/pkp-report\""))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.PUBLIC_KEY_PINS_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class HpkpWithReportUriInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.httpPublicKeyPinning(hpkp ->
							hpkp
								.addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=")
								.reportUri("https://example.net/pkp-report")
						)
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenContentSecurityPolicyConfiguredThenContentSecurityPolicyHeaderInResponse() throws Exception {
		this.spring.register(ContentSecurityPolicyDefaultConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'self'"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY);
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyDefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("default-src 'self'");
			// @formatter:on
		}
	}

	@Test
	public void getWhenContentSecurityPolicyWithReportOnlyThenContentSecurityPolicyReportOnlyHeaderInResponse() throws Exception {
		this.spring.register(ContentSecurityPolicyReportOnlyConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY,
						"default-src 'self'; script-src trustedscripts.example.com"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyReportOnlyConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("default-src 'self'; script-src trustedscripts.example.com")
					.reportOnly();
			// @formatter:on
		}
	}

	@Test
	public void getWhenContentSecurityPolicyWithReportOnlyInLambdaThenContentSecurityPolicyReportOnlyHeaderInResponse()
			throws Exception {
		this.spring.register(ContentSecurityPolicyReportOnlyInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY,
						"default-src 'self'; script-src trustedscripts.example.com"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY);
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyReportOnlyInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.contentSecurityPolicy(csp ->
							csp
								.policyDirectives("default-src 'self'; script-src trustedscripts.example.com")
								.reportOnly()
						)
				);
			// @formatter:on
		}
	}

	@Test
	public void configureWhenContentSecurityPolicyEmptyThenException() {
		assertThatThrownBy(() -> this.spring.register(ContentSecurityPolicyInvalidConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyInvalidConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.contentSecurityPolicy("");
			// @formatter:on
		}
	}

	@Test
	public void configureWhenContentSecurityPolicyEmptyInLambdaThenException() {
		assertThatThrownBy(() -> this.spring.register(ContentSecurityPolicyInvalidInLambdaConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyInvalidInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.contentSecurityPolicy(csp ->
								csp.policyDirectives("")
						)
				);
			// @formatter:on
		}
	}

	@Test
	public void configureWhenContentSecurityPolicyNoPolicyDirectivesInLambdaThenDefaultHeaderValue() throws Exception {
		this.spring.register(ContentSecurityPolicyNoDirectivesInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.CONTENT_SECURITY_POLICY,
						"default-src 'self'"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.CONTENT_SECURITY_POLICY);
	}

	@EnableWebSecurity
	static class ContentSecurityPolicyNoDirectivesInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.contentSecurityPolicy(withDefaults())
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenReferrerPolicyConfiguredThenReferrerPolicyHeaderInResponse() throws Exception {
		this.spring.register(ReferrerPolicyDefaultConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string("Referrer-Policy", ReferrerPolicy.NO_REFERRER.getPolicy()))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@EnableWebSecurity
	static class ReferrerPolicyDefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.referrerPolicy();
			// @formatter:on
		}
	}

	@Test
	public void getWhenReferrerPolicyInLambdaThenReferrerPolicyHeaderInResponse() throws Exception {
		this.spring.register(ReferrerPolicyDefaultInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string("Referrer-Policy", ReferrerPolicy.NO_REFERRER.getPolicy()))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@EnableWebSecurity
	static class ReferrerPolicyDefaultInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.referrerPolicy()
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenReferrerPolicyConfiguredWithCustomValueThenReferrerPolicyHeaderWithCustomValueInResponse()
			throws Exception {
		this.spring.register(ReferrerPolicyCustomConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string("Referrer-Policy", ReferrerPolicy.SAME_ORIGIN.getPolicy()))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@EnableWebSecurity
	static class ReferrerPolicyCustomConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.referrerPolicy(ReferrerPolicy.SAME_ORIGIN);
			// @formatter:on
		}
	}

	@Test
	public void getWhenReferrerPolicyConfiguredWithCustomValueInLambdaThenCustomValueInResponse() throws Exception {
		this.spring.register(ReferrerPolicyCustomInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string("Referrer-Policy", ReferrerPolicy.SAME_ORIGIN.getPolicy()))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Referrer-Policy");
	}

	@EnableWebSecurity
	static class ReferrerPolicyCustomInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.referrerPolicy(referrerPolicy ->
								referrerPolicy.policy(ReferrerPolicy.SAME_ORIGIN)
						)
				);
			// @formatter:on
		}
	}

	@Test
	public void getWhenFeaturePolicyConfiguredThenFeaturePolicyHeaderInResponse() throws Exception {
		this.spring.register(FeaturePolicyConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string("Feature-Policy", "geolocation 'self'"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly("Feature-Policy");
	}

	@EnableWebSecurity
	static class FeaturePolicyConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.featurePolicy("geolocation 'self'");
			// @formatter:on
		}
	}

	@Test
	public void configureWhenFeaturePolicyEmptyThenException() {
		assertThatThrownBy(() -> this.spring.register(FeaturePolicyInvalidConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@EnableWebSecurity
	static class FeaturePolicyInvalidConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.featurePolicy("");
			// @formatter:on
		}
	}

	@Test
	public void getWhenHstsConfiguredWithPreloadThenStrictTransportSecurityHeaderWithPreloadInResponse()
			throws Exception {
		this.spring.register(HstsWithPreloadConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY,
						"max-age=31536000 ; includeSubDomains ; preload"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.STRICT_TRANSPORT_SECURITY);
	}

	@EnableWebSecurity
	static class HstsWithPreloadConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.defaultsDisabled()
					.httpStrictTransportSecurity()
						.preload(true);
			// @formatter:on
		}
	}

	@Test
	public void getWhenHstsConfiguredWithPreloadInLambdaThenStrictTransportSecurityHeaderWithPreloadInResponse()
			throws Exception {
		this.spring.register(HstsWithPreloadInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY,
						"max-age=31536000 ; includeSubDomains ; preload"))
				.andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactly(HttpHeaders.STRICT_TRANSPORT_SECURITY);
	}

	@EnableWebSecurity
	static class HstsWithPreloadInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers(headers ->
					headers
						.defaultsDisabled()
						.httpStrictTransportSecurity(hstsConfig -> hstsConfig.preload(true))
				);
			// @formatter:on
		}
	}
}
