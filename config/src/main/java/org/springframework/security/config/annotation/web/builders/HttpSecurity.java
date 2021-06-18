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
package org.springframework.security.config.annotation.web.builders;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.JeeConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.PortMapperConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.openid.OpenIDLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.saml2.Saml2LoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

/**
 * https://andyboke.blog.csdn.net/article/details/90183080
 * <p>
 * HttpSecurity是Spring Security Config用于配置http请求安全控制的安全构建器(类似于Spring Security XML配置中的http命名空间配置部分)，它的构建目标是一个SecurityFilterChain,
 * 实现类使用DefaultSecurityFilterChain。该目标SecurityFilterChain最终会被Spring Security的安全过滤器FilterChainProxy所持有和应用于相应的http请求的安全控制。
 * <p>
 * HttpSecurity缺省情况下应用到所有的请求，不过也可通过使用其方法#requestMatcher(RequestMatcher)(或者其他类似的手段)限制它仅应用到某些请求上。
 * <p>
 * 安全构建器HttpSecurity和WebSecurity的区别是 :
 * <p>
 * WebSecurity不仅通过HttpSecurity定义某些请求的安全控制，也通过其他方式定义其他某些请求可以忽略安全控制;
 * HttpSecurity仅用于定义需要安全控制的请求(当然HttpSecurity也可以指定某些请求不需要安全控制);
 * 可以认为HttpSecurity是WebSecurity的一部分，WebSecurity是包含HttpSecurity的更大的一个概念;
 * 注意 : 这里是从语义上讲，而不是从实现层面的表示形式上讲；
 * <p>
 * 构建目标不同
 * WebSecurity构建目标是整个Spring Security安全过滤器FilterChainProxy,
 * 而HttpSecurity的构建目标仅仅是FilterChainProxy中的一个SecurityFilterChain。
 * <p>
 * <p>
 * HttpSecurity类似于Spring Security's XML中的http标签，用于对具体的请求进行安全认证，默认 情况下是对所有的请求，
 * <p>
 * 方法	说明
 * openidLogin()	用于基于 OpenId 的验证
 * headers()	将安全标头添加到响应,比如说简单的 XSS 保护
 * cors()	配置跨域资源共享（ CORS ）
 * sessionManagement()	允许配置会话管理
 * portMapper()	允许配置一个PortMapper(HttpSecurity#(getSharedObject(class)))，其他提供SecurityConfigurer的对象使用 PortMapper 从 HTTP 重定向到 HTTPS 或者从 HTTPS 重定向到 HTTP。默认情况下，Spring Security使用一个PortMapperImpl映射 HTTP 端口8080到 HTTPS 端口8443，HTTP 端口80到 HTTPS 端口443
 * jee()	配置基于容器的预认证。 在这种情况下，认证由Servlet容器管理
 * x509()	配置基于x509的认证
 * rememberMe	允许配置“记住我”的验证
 * authorizeRequests()	允许基于使用HttpServletRequest限制访问
 * requestCache()	允许配置请求缓存
 * exceptionHandling()	允许配置错误处理
 * securityContext()	在HttpServletRequests之间的SecurityContextHolder上设置SecurityContext的管理。 当使用WebSecurityConfigurerAdapter时，这将自动应用
 * servletApi()	将HttpServletRequest方法与在其上找到的值集成到SecurityContext中。 当使用WebSecurityConfigurerAdapter时，这将自动应用
 * csrf()	添加 CSRF 支持，使用WebSecurityConfigurerAdapter时，默认启用
 * logout()	添加退出登录支持。当使用WebSecurityConfigurerAdapter时，这将自动应用。默认情况是，访问URL”/ logout”，使HTTP Session无效来清除用户，清除已配置的任何#rememberMe()身份验证，清除SecurityContextHolder，然后重定向到”/login?success”
 * anonymous()	允许配置匿名用户的表示方法。 当与WebSecurityConfigurerAdapter结合使用时，这将自动应用。 默认情况下，匿名用户将使用org.springframework.security.authentication.AnonymousAuthenticationToken表示，并包含角色 “ROLE_ANONYMOUS”
 * formLogin()	指定支持基于表单的身份验证。如果未指定FormLoginConfigurer#loginPage(String)，则将生成默认登录页面
 * oauth2Login()	根据外部OAuth 2.0或OpenID Connect 1.0提供程序配置身份验证
 * requiresChannel()	配置通道安全。为了使该配置有用，必须提供至少一个到所需信道的映射
 * httpBasic()	配置 Http Basic 验证
 * addFilterBefore()	在指定的Filter类之前添加过滤器
 * addFilterAt()	在指定的Filter类的位置添加过滤器
 * addFilterAfter()	在指定的Filter类的之后添加过滤器
 * and()	连接以上策略的连接器，用来组合安全策略。实际上就是”而且”的意思
 * A {@link HttpSecurity} is similar to Spring Security's XML &lt;http&gt; element in the
 * namespace configuration. It allows configuring web based security for specific http
 * requests. By default it will be applied to all requests, but can be restricted using
 * {@link #requestMatcher(RequestMatcher)} or other similar methods.
 *
 * <h2>Example Usage</h2>
 * <p>
 * The most basic form based configuration can be seen below. The configuration will
 * require that any URL that is requested will require a User with the role "ROLE_USER".
 * It also defines an in memory authentication scheme with a user that has the username
 * "user", the password "password", and the role "ROLE_USER". For additional examples,
 * refer to the Java Doc of individual methods on {@link HttpSecurity}.
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
 *
 * 	&#064;Override
 * 	protected void configure(HttpSecurity http) throws Exception {
 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
 *    }
 *
 * 	&#064;Override
 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
 *    }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @see EnableWebSecurity
 * @since 3.2
 */
public final class HttpSecurity extends
		AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity>
		implements SecurityBuilder<DefaultSecurityFilterChain>,
		HttpSecurityBuilder<HttpSecurity> {
	//从变量名就可以看到是请求匹配过滤的配置信息
	private final RequestMatcherConfigurer requestMatcherConfigurer;
	//过滤器列表?
	private List<Filter> filters = new ArrayList<>();
	//匹配任何请求的匹配器
	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
	//过滤器比较.....啥啥啥不知道
	private FilterComparator comparator = new FilterComparator();

	/**
	 * Creates a new instance
	 * 除了设置了共享对象之外，唯一值得一提的就是ApplicationContext 作为共享对象传递进来了，哈哈，毕竟spring security再牛逼，再spring面前还是得装装小媳妇的
	 *
	 * @param objectPostProcessor   the {@link ObjectPostProcessor} that should be used
	 * @param authenticationBuilder the {@link AuthenticationManagerBuilder} to use for
	 *                              additional updates
	 * @param sharedObjects         the shared Objects to initialize the {@link HttpSecurity} with
	 * @see WebSecurityConfiguration
	 */
	@SuppressWarnings("unchecked")
	public HttpSecurity(ObjectPostProcessor<Object> objectPostProcessor,
			AuthenticationManagerBuilder authenticationBuilder,
			Map<Class<?>, Object> sharedObjects) {
		super(objectPostProcessor);
		Assert.notNull(authenticationBuilder, "authenticationBuilder cannot be null");
		setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
		for (Map.Entry<Class<?>, Object> entry : sharedObjects
				.entrySet()) {
			setSharedObject((Class<Object>) entry.getKey(), entry.getValue());
		}
		ApplicationContext context = (ApplicationContext) sharedObjects
				.get(ApplicationContext.class);
		this.requestMatcherConfigurer = new RequestMatcherConfigurer(context);
	}

	/**
	 * 获取应用上下文
	 *
	 * @return
	 */
	private ApplicationContext getContext() {
		return getSharedObject(ApplicationContext.class);
	}

	/**
	 * 用于基于 OpenId 的验证
	 * Allows configuring OpenID based authentication.
	 *
	 * <h2>Example Configurations</h2>
	 * <p>
	 * A basic example accepting the defaults and not using attribute exchange:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().openidLogin()
	 * 				.permitAll();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication()
	 * 				// the username must match the OpenID of the user you are
	 * 				// logging in with
	 * 				.withUser(
	 * 						&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
	 * 				.password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * A more advanced example demonstrating using attribute exchange and providing a
	 * custom AuthenticationUserDetailsService that will make any user that authenticates
	 * a valid user.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) {
	 * 		http.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;)
	 * 				.hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 				.openidLogin()
	 * 				.loginPage(&quot;/login&quot;)
	 * 				.permitAll()
	 * 				.authenticationUserDetailsService(
	 * 						new AutoProvisioningUserDetailsService())
	 * 				.attributeExchange(&quot;https://www.google.com/.*&quot;).attribute(&quot;email&quot;)
	 * 				.type(&quot;https://axschema.org/contact/email&quot;).required(true).and()
	 * 				.attribute(&quot;firstname&quot;).type(&quot;https://axschema.org/namePerson/first&quot;)
	 * 				.required(true).and().attribute(&quot;lastname&quot;)
	 * 				.type(&quot;https://axschema.org/namePerson/last&quot;).required(true).and().and()
	 * 				.attributeExchange(&quot;.*yahoo.com.*&quot;).attribute(&quot;email&quot;)
	 * 				.type(&quot;https://schema.openid.net/contact/email&quot;).required(true).and()
	 * 				.attribute(&quot;fullname&quot;).type(&quot;https://axschema.org/namePerson&quot;)
	 * 				.required(true).and().and().attributeExchange(&quot;.*myopenid.com.*&quot;)
	 * 				.attribute(&quot;email&quot;).type(&quot;https://schema.openid.net/contact/email&quot;)
	 * 				.required(true).and().attribute(&quot;fullname&quot;)
	 * 				.type(&quot;https://schema.openid.net/namePerson&quot;).required(true);
	 *    }
	 * }
	 *
	 * public class AutoProvisioningUserDetailsService implements
	 * 		AuthenticationUserDetailsService&lt;OpenIDAuthenticationToken&gt; {
	 * 	public UserDetails loadUserDetails(OpenIDAuthenticationToken token)
	 * 			throws UsernameNotFoundException {
	 * 		return new User(token.getName(), &quot;NOTUSED&quot;,
	 * 				AuthorityUtils.createAuthorityList(&quot;ROLE_USER&quot;));
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link OpenIDLoginConfigurer} for further customizations.
	 * @throws Exception
	 * @see OpenIDLoginConfigurer
	 */
	public OpenIDLoginConfigurer<HttpSecurity> openidLogin() throws Exception {
		return getOrApply(new OpenIDLoginConfigurer<>());
	}

	/**
	 * Allows configuring OpenID based authentication.
	 *
	 * <h2>Example Configurations</h2>
	 * <p>
	 * A basic example accepting the defaults and not using attribute exchange:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.openidLogin(openidLogin ->
	 * 				openidLogin
	 * 					.permitAll()
	 * 			);
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication()
	 * 				// the username must match the OpenID of the user you are
	 * 				// logging in with
	 * 				.withUser(
	 * 						&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
	 * 				.password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * A more advanced example demonstrating using attribute exchange and providing a
	 * custom AuthenticationUserDetailsService that will make any user that authenticates
	 * a valid user.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.openidLogin(openidLogin ->
	 * 				openidLogin
	 * 					.loginPage(&quot;/login&quot;)
	 * 					.permitAll()
	 * 					.authenticationUserDetailsService(
	 * 						new AutoProvisioningUserDetailsService())
	 * 					.attributeExchange(googleExchange ->
	 * 						googleExchange
	 * 							.identifierPattern(&quot;https://www.google.com/.*&quot;)
	 * 							.attribute(emailAttribute ->
	 * 								emailAttribute
	 * 									.name(&quot;email&quot;)
	 * 									.type(&quot;https://axschema.org/contact/email&quot;)
	 * 									.required(true)
	 * 							)
	 * 							.attribute(firstnameAttribute ->
	 * 								firstnameAttribute
	 * 									.name(&quot;firstname&quot;)
	 * 									.type(&quot;https://axschema.org/namePerson/first&quot;)
	 * 									.required(true)
	 * 							)
	 * 							.attribute(lastnameAttribute ->
	 * 								lastnameAttribute
	 * 									.name(&quot;lastname&quot;)
	 * 									.type(&quot;https://axschema.org/namePerson/last&quot;)
	 * 									.required(true)
	 * 							)
	 * 					)
	 * 					.attributeExchange(yahooExchange ->
	 * 						yahooExchange
	 * 							.identifierPattern(&quot;.*yahoo.com.*&quot;)
	 * 							.attribute(emailAttribute ->
	 * 								emailAttribute
	 * 									.name(&quot;email&quot;)
	 * 									.type(&quot;https://schema.openid.net/contact/email&quot;)
	 * 									.required(true)
	 * 							)
	 * 							.attribute(fullnameAttribute ->
	 * 								fullnameAttribute
	 * 									.name(&quot;fullname&quot;)
	 * 									.type(&quot;https://axschema.org/namePerson&quot;)
	 * 									.required(true)
	 * 							)
	 * 					)
	 * 			);
	 *    }
	 * }
	 *
	 * public class AutoProvisioningUserDetailsService implements
	 * 		AuthenticationUserDetailsService&lt;OpenIDAuthenticationToken&gt; {
	 * 	public UserDetails loadUserDetails(OpenIDAuthenticationToken token)
	 * 			throws UsernameNotFoundException {
	 * 		return new User(token.getName(), &quot;NOTUSED&quot;,
	 * 				AuthorityUtils.createAuthorityList(&quot;ROLE_USER&quot;));
	 *    }
	 * }
	 * </pre>
	 *
	 * @param openidLoginCustomizer the {@link Customizer} to provide more options for
	 *                              the {@link OpenIDLoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see OpenIDLoginConfigurer
	 */
	public HttpSecurity openidLogin(Customizer<OpenIDLoginConfigurer<HttpSecurity>> openidLoginCustomizer) throws Exception {
		openidLoginCustomizer.customize(getOrApply(new OpenIDLoginConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Adds the Security headers to the response. This is activated by default when using
	 * {@link WebSecurityConfigurerAdapter}'s default constructor. Accepting the
	 * default provided by {@link WebSecurityConfigurerAdapter} or only invoking
	 * {@link #headers()} without invoking additional methods on it, is the equivalent of:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers()
	 *                 .contentTypeOptions()
	 *                 .and()
	 *                 .xssProtection()
	 *                 .and()
	 *                 .cacheControl()
	 *                 .and()
	 *                 .httpStrictTransportSecurity()
	 *                 .and()
	 *                 .frameOptions()
	 *                 .and()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 * <p>
	 * You can disable the headers using the following:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers().disable()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 * <p>
	 * You can enable only a few of the headers by first invoking
	 * {@link HeadersConfigurer#defaultsDisabled()}
	 * and then invoking the appropriate methods on the {@link #headers()} result.
	 * For example, the following will enable {@link HeadersConfigurer#cacheControl()} and
	 * {@link HeadersConfigurer#frameOptions()} only.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers()
	 *                  .defaultsDisabled()
	 *                  .cacheControl()
	 *                  .and()
	 *                  .frameOptions()
	 *                  .and()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 * <p>
	 * You can also choose to keep the defaults but explicitly disable a subset of headers.
	 * For example, the following will enable all the default headers except
	 * {@link HeadersConfigurer#frameOptions()}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .headers()
	 *                  .frameOptions()
	 *                  	.disable()
	 *                  .and()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 *
	 * @return the {@link HeadersConfigurer} for further customizations
	 * @throws Exception
	 * @see HeadersConfigurer
	 */
	public HeadersConfigurer<HttpSecurity> headers() throws Exception {
		return getOrApply(new HeadersConfigurer<>());
	}

	/**
	 * Adds the Security headers to the response. This is activated by default when using
	 * {@link WebSecurityConfigurerAdapter}'s default constructor.
	 *
	 * <h2>Example Configurations</h2>
	 * <p>
	 * Accepting the default provided by {@link WebSecurityConfigurerAdapter} or only invoking
	 * {@link #headers()} without invoking additional methods on it, is the equivalent of:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers(headers ->
	 * 				headers
	 * 					.contentTypeOptions(withDefaults())
	 * 					.xssProtection(withDefaults())
	 * 					.cacheControl(withDefaults())
	 * 					.httpStrictTransportSecurity(withDefaults())
	 * 					.frameOptions(withDefaults()
	 * 			);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * You can disable the headers using the following:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers(headers -> headers.disable());
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * You can enable only a few of the headers by first invoking
	 * {@link HeadersConfigurer#defaultsDisabled()}
	 * and then invoking the appropriate methods on the {@link #headers()} result.
	 * For example, the following will enable {@link HeadersConfigurer#cacheControl()} and
	 * {@link HeadersConfigurer#frameOptions()} only.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.headers(headers ->
	 * 				headers
	 * 			 		.defaultsDisabled()
	 * 			 		.cacheControl(withDefaults())
	 * 			 		.frameOptions(withDefaults())
	 * 			);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * You can also choose to keep the defaults but explicitly disable a subset of headers.
	 * For example, the following will enable all the default headers except
	 * {@link HeadersConfigurer#frameOptions()}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *  protected void configure(HttpSecurity http) throws Exception {
	 *  	http
	 *  		.headers(headers ->
	 *  			headers
	 *  				.frameOptions(frameOptions -> frameOptions.disable())
	 *  		);
	 * }
	 * </pre>
	 *
	 * @param headersCustomizer the {@link Customizer} to provide more options for
	 *                          the {@link HeadersConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity headers(Customizer<HeadersConfigurer<HttpSecurity>> headersCustomizer) throws Exception {
		headersCustomizer.customize(getOrApply(new HeadersConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Adds a {@link CorsFilter} to be used. If a bean by the name of corsFilter is
	 * provided, that {@link CorsFilter} is used. Else if corsConfigurationSource is
	 * defined, then that {@link CorsConfiguration} is used. Otherwise, if Spring MVC is
	 * on the classpath a {@link HandlerMappingIntrospector} is used.
	 *
	 * @return the {@link CorsConfigurer} for customizations
	 * @throws Exception
	 */
	public CorsConfigurer<HttpSecurity> cors() throws Exception {
		return getOrApply(new CorsConfigurer<>());
	}

	/**
	 * Adds a {@link CorsFilter} to be used. If a bean by the name of corsFilter is
	 * provided, that {@link CorsFilter} is used. Else if corsConfigurationSource is
	 * defined, then that {@link CorsConfiguration} is used. Otherwise, if Spring MVC is
	 * on the classpath a {@link HandlerMappingIntrospector} is used.
	 * You can enable CORS using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CorsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .cors(withDefaults());
	 *     }
	 * }
	 * </pre>
	 *
	 * @param corsCustomizer the {@link Customizer} to provide more options for
	 *                       the {@link CorsConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity cors(Customizer<CorsConfigurer<HttpSecurity>> corsCustomizer) throws Exception {
		corsCustomizer.customize(getOrApply(new CorsConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * 配置会员管理
	 * Allows configuring of Session Management.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration demonstrates how to enforce that only a single instance
	 * of a user is authenticated at a time. If a user authenticates with the username
	 * "user" without logging out and an attempt to authenticate with "user" is made the
	 * first session will be forcibly terminated and sent to the "/login?expired" URL.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SessionManagementSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().anyRequest().hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and().sessionManagement().maximumSessions(1)
	 * 				.expiredUrl(&quot;/login?expired&quot;);
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * When using {@link SessionManagementConfigurer#maximumSessions(int)}, do not forget
	 * to configure {@link HttpSessionEventPublisher} for the application to ensure that
	 * expired sessions are cleaned up.
	 * <p>
	 * In a web.xml this can be configured using the following:
	 *
	 * <pre>
	 * &lt;listener&gt;
	 *      &lt;listener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
	 * &lt;/listener&gt;
	 * </pre>
	 * <p>
	 * Alternatively,
	 * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
	 * could return true.
	 *
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 * @throws Exception
	 */
	public SessionManagementConfigurer<HttpSecurity> sessionManagement() throws Exception {
		return getOrApply(new SessionManagementConfigurer<>());
	}

	/**
	 * Allows configuring of Session Management.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration demonstrates how to enforce that only a single instance
	 * of a user is authenticated at a time. If a user authenticates with the username
	 * "user" without logging out and an attempt to authenticate with "user" is made the
	 * first session will be forcibly terminated and sent to the "/login?expired" URL.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SessionManagementSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.anyRequest().hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(formLogin ->
	 * 				formLogin
	 * 					.permitAll()
	 * 			)
	 * 			.sessionManagement(sessionManagement ->
	 * 				sessionManagement
	 * 					.sessionConcurrency(sessionConcurrency ->
	 * 						sessionConcurrency
	 * 							.maximumSessions(1)
	 * 							.expiredUrl(&quot;/login?expired&quot;)
	 * 					)
	 * 			);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * When using {@link SessionManagementConfigurer#maximumSessions(int)}, do not forget
	 * to configure {@link HttpSessionEventPublisher} for the application to ensure that
	 * expired sessions are cleaned up.
	 * <p>
	 * In a web.xml this can be configured using the following:
	 *
	 * <pre>
	 * &lt;listener&gt;
	 *      &lt;listener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
	 * &lt;/listener&gt;
	 * </pre>
	 * <p>
	 * Alternatively,
	 * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
	 * could return true.
	 *
	 * @param sessionManagementCustomizer the {@link Customizer} to provide more options for
	 *                                    the {@link SessionManagementConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> sessionManagementCustomizer) throws Exception {
		sessionManagementCustomizer.customize(getOrApply(new SessionManagementConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring a {@link PortMapper} that is available from
	 * {@link HttpSecurity#getSharedObject(Class)}. Other provided
	 * {@link SecurityConfigurer} objects use this configured {@link PortMapper} as a
	 * default {@link PortMapper} when redirecting from HTTP to HTTPS or from HTTPS to
	 * HTTP (for example when used in combination with {@link #requiresChannel()}. By
	 * default Spring Security uses a {@link PortMapperImpl} which maps the HTTP port 8080
	 * to the HTTPS port 8443 and the HTTP port of 80 to the HTTPS port of 443.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration will ensure that redirects within Spring Security from
	 * HTTP of a port of 9090 will redirect to HTTPS port of 9443 and the HTTP port of 80
	 * to the HTTPS port of 443.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and()
	 * 				// Example portMapper() configuration
	 * 				.portMapper().http(9090).mapsTo(9443).http(80).mapsTo(443);
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link PortMapperConfigurer} for further customizations
	 * @throws Exception
	 * @see #requiresChannel()
	 */
	public PortMapperConfigurer<HttpSecurity> portMapper() throws Exception {
		return getOrApply(new PortMapperConfigurer<>());
	}

	/**
	 * Allows configuring a {@link PortMapper} that is available from
	 * {@link HttpSecurity#getSharedObject(Class)}. Other provided
	 * {@link SecurityConfigurer} objects use this configured {@link PortMapper} as a
	 * default {@link PortMapper} when redirecting from HTTP to HTTPS or from HTTPS to
	 * HTTP (for example when used in combination with {@link #requiresChannel()}. By
	 * default Spring Security uses a {@link PortMapperImpl} which maps the HTTP port 8080
	 * to the HTTPS port 8443 and the HTTP port of 80 to the HTTPS port of 443.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration will ensure that redirects within Spring Security from
	 * HTTP of a port of 9090 will redirect to HTTPS port of 9443 and the HTTP port of 80
	 * to the HTTPS port of 443.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requiresChannel(requiresChannel ->
	 * 				requiresChannel
	 * 					.anyRequest().requiresSecure()
	 * 			)
	 * 			.portMapper(portMapper ->
	 * 				portMapper
	 * 					.http(9090).mapsTo(9443)
	 * 					.http(80).mapsTo(443)
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param portMapperCustomizer the {@link Customizer} to provide more options for
	 *                             the {@link PortMapperConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see #requiresChannel()
	 */
	public HttpSecurity portMapper(Customizer<PortMapperConfigurer<HttpSecurity>> portMapperCustomizer) throws Exception {
		portMapperCustomizer.customize(getOrApply(new PortMapperConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures container based pre authentication. In this case, authentication
	 * is managed by the Servlet Container.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration will use the principal found on the
	 * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
	 * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
	 * 		// Example jee() configuration
	 * 				.jee().mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * Developers wishing to use pre authentication with the container will need to ensure
	 * their web.xml configures the security constraints. For example, the web.xml (there
	 * is no equivalent Java based configuration supported by the Servlet specification)
	 * might look like:
	 *
	 * <pre>
	 * &lt;login-config&gt;
	 *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
	 *     &lt;form-login-config&gt;
	 *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
	 *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
	 *     &lt;/form-login-config&gt;
	 * &lt;/login-config&gt;
	 *
	 * &lt;security-role&gt;
	 *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 * &lt;/security-role&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
	 *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
	 *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 * &lt;/security-constraint&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
	 *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 *     &lt;auth-constraint&gt;
	 *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 *     &lt;/auth-constraint&gt;
	 * &lt;/security-constraint&gt;
	 * </pre>
	 * <p>
	 * Last you will need to configure your container to contain the user with the correct
	 * roles. This configuration is specific to the Servlet Container, so consult your
	 * Servlet Container's documentation.
	 *
	 * @return the {@link JeeConfigurer} for further customizations
	 * @throws Exception
	 */
	public JeeConfigurer<HttpSecurity> jee() throws Exception {
		return getOrApply(new JeeConfigurer<>());
	}

	/**
	 * Configures container based pre authentication. In this case, authentication
	 * is managed by the Servlet Container.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration will use the principal found on the
	 * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
	 * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.jee(jee ->
	 * 				jee
	 * 					.mappableRoles(&quot;USER&quot;, &quot;ADMIN&quot;)
	 * 			);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * Developers wishing to use pre authentication with the container will need to ensure
	 * their web.xml configures the security constraints. For example, the web.xml (there
	 * is no equivalent Java based configuration supported by the Servlet specification)
	 * might look like:
	 *
	 * <pre>
	 * &lt;login-config&gt;
	 *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
	 *     &lt;form-login-config&gt;
	 *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
	 *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
	 *     &lt;/form-login-config&gt;
	 * &lt;/login-config&gt;
	 *
	 * &lt;security-role&gt;
	 *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 * &lt;/security-role&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
	 *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
	 *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
	 *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 * &lt;/security-constraint&gt;
	 * &lt;security-constraint&gt;
	 *     &lt;web-resource-collection&gt;
	 *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
	 *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
	 *     &lt;/web-resource-collection&gt;
	 *     &lt;auth-constraint&gt;
	 *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
	 *     &lt;/auth-constraint&gt;
	 * &lt;/security-constraint&gt;
	 * </pre>
	 * <p>
	 * Last you will need to configure your container to contain the user with the correct
	 * roles. This configuration is specific to the Servlet Container, so consult your
	 * Servlet Container's documentation.
	 *
	 * @param jeeCustomizer the {@link Customizer} to provide more options for
	 *                      the {@link JeeConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity jee(Customizer<JeeConfigurer<HttpSecurity>> jeeCustomizer) throws Exception {
		jeeCustomizer.customize(getOrApply(new JeeConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures X509 based pre authentication.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration will attempt to extract the username from the X509
	 * certificate. Remember that the Servlet Container will need to be configured to
	 * request client certificates in order for this to work.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
	 * 		// Example x509() configuration
	 * 				.x509();
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link X509Configurer} for further customizations
	 * @throws Exception
	 */
	public X509Configurer<HttpSecurity> x509() throws Exception {
		return getOrApply(new X509Configurer<>());
	}

	/**
	 * Configures X509 based pre authentication.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration will attempt to extract the username from the X509
	 * certificate. Remember that the Servlet Container will need to be configured to
	 * request client certificates in order for this to work.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.x509(withDefaults());
	 *    }
	 * }
	 * </pre>
	 *
	 * @param x509Customizer the {@link Customizer} to provide more options for
	 *                       the {@link X509Configurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity x509(Customizer<X509Configurer<HttpSecurity>> x509Customizer) throws Exception {
		x509Customizer.customize(getOrApply(new X509Configurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * 允许配置“记住我”身份验证。
	 * Allows configuring of Remember Me authentication.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration demonstrates how to allow token based remember me
	 * authentication. Upon authenticating if the HTTP parameter named "remember-me"
	 * exists, then the user will be remembered even after their
	 * {@link javax.servlet.http.HttpSession} expires.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.permitAll().and()
	 * 				// Example Remember Me Configuration
	 * 				.rememberMe();
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link RememberMeConfigurer} for further customizations
	 * @throws Exception
	 */
	public RememberMeConfigurer<HttpSecurity> rememberMe() throws Exception {
		return getOrApply(new RememberMeConfigurer<>());
	}

	/**
	 * Allows configuring of Remember Me authentication.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration demonstrates how to allow token based remember me
	 * authentication. Upon authenticating if the HTTP parameter named "remember-me"
	 * exists, then the user will be remembered even after their
	 * {@link javax.servlet.http.HttpSession} expires.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			.rememberMe(withDefaults());
	 *    }
	 * }
	 * </pre>
	 *
	 * @param rememberMeCustomizer the {@link Customizer} to provide more options for
	 *                             the {@link RememberMeConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity rememberMe(Customizer<RememberMeConfigurer<HttpSecurity>> rememberMeCustomizer) throws Exception {
		rememberMeCustomizer.customize(getOrApply(new RememberMeConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * 开启配置
	 * 允许使用{@link RequestMatcher}实现（即通过URL模式）基于{@link HttpServletRequest}限制访问。
	 * Allows restricting access based upon the {@link HttpServletRequest} using
	 * {@link RequestMatcher} implementations (i.e. via URL patterns).
	 * <p>
	 * 实例如下，
	 * 配置所有的urls需要ROLE_USER的角色，
	 * <h2>Example Configurations</h2>
	 * <p>
	 * The most basic example is to configure all URLs to require the role "ROLE_USER".
	 * The configuration below requires authentication to every URL and will grant access
	 * to both the user "admin" and "user".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
	 * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;ADMIN&quot;, &quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * We can also configure multiple URLs. The configuration below requires
	 * authentication to every URL and will grant access to URLs starting with /admin/ to
	 * only the "admin" user. All other URLs either user can access.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;)
	 * 				.and().withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;ADMIN&quot;, &quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * Note that the matchers are considered in order. Therefore, the following is invalid
	 * because the first matcher matches every request and will never get to the second
	 * mapping:
	 *
	 * <pre>
	 * http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).antMatchers(&quot;/admin/**&quot;)
	 * 		.hasRole(&quot;ADMIN&quot;)
	 * </pre>
	 *
	 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
	 * @throws Exception
	 * @see #requestMatcher(RequestMatcher)
	 */
	public ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests()
			throws Exception {
		//获取应用上下文
		ApplicationContext context = getContext();
		//
		return getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context))
				.getRegistry();
	}

	/**
	 * Allows restricting access based upon the {@link HttpServletRequest} using
	 * {@link RequestMatcher} implementations (i.e. via URL patterns).
	 *
	 * <h2>Example Configurations</h2>
	 * <p>
	 * The most basic example is to configure all URLs to require the role "ROLE_USER".
	 * The configuration below requires authentication to every URL and will grant access
	 * to both the user "admin" and "user".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * We can also configure multiple URLs. The configuration below requires
	 * authentication to every URL and will grant access to URLs starting with /admin/ to
	 * only the "admin" user. All other URLs either user can access.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * Note that the matchers are considered in order. Therefore, the following is invalid
	 * because the first matcher matches every request and will never get to the second
	 * mapping:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		 http
	 * 		 	.authorizeRequests(authorizeRequests ->
	 * 		 		authorizeRequests
	 * 			 		.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			 		.antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
	 * 		 	);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param authorizeRequestsCustomizer the {@link Customizer} to provide more options for
	 *                                    the {@link ExpressionUrlAuthorizationConfigurer.ExpressionInterceptUrlRegistry}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see #requestMatcher(RequestMatcher)
	 */
	public HttpSecurity authorizeRequests(Customizer<ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry> authorizeRequestsCustomizer)
			throws Exception {
		ApplicationContext context = getContext();
		authorizeRequestsCustomizer.customize(getOrApply(new ExpressionUrlAuthorizationConfigurer<>(context))
				.getRegistry());
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring the Request Cache. For example, a protected page (/protected)
	 * may be requested prior to authentication. The application will redirect the user to
	 * a login page. After authentication, Spring Security will redirect the user to the
	 * originally requested protected page (/protected). This is automatically applied
	 * when using {@link WebSecurityConfigurerAdapter}.
	 *
	 * @return the {@link RequestCacheConfigurer} for further customizations
	 * @throws Exception
	 */
	public RequestCacheConfigurer<HttpSecurity> requestCache() throws Exception {
		return getOrApply(new RequestCacheConfigurer<>());
	}

	/**
	 * Allows configuring the Request Cache. For example, a protected page (/protected)
	 * may be requested prior to authentication. The application will redirect the user to
	 * a login page. After authentication, Spring Security will redirect the user to the
	 * originally requested protected page (/protected). This is automatically applied
	 * when using {@link WebSecurityConfigurerAdapter}.
	 *
	 * <h2>Example Custom Configuration</h2>
	 * <p>
	 * The following example demonstrates how to disable request caching.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestCacheDisabledSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.requestCache(requestCache ->
	 * 				requestCache.disable()
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param requestCacheCustomizer the {@link Customizer} to provide more options for
	 *                               the {@link RequestCacheConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity requestCache(Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer)
			throws Exception {
		requestCacheCustomizer.customize(getOrApply(new RequestCacheConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring exception handling. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}.
	 *
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 * @throws Exception
	 */
	public ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling() throws Exception {
		return getOrApply(new ExceptionHandlingConfigurer<>());
	}

	/**
	 * Allows configuring exception handling. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}.
	 *
	 * <h2>Example Custom Configuration</h2>
	 * <p>
	 * The following customization will ensure that users who are denied access are forwarded
	 * to the page "/errors/access-denied".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ExceptionHandlingSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			// sample exception handling customization
	 * 			.exceptionHandling(exceptionHandling ->
	 * 				exceptionHandling
	 * 					.accessDeniedPage(&quot;/errors/access-denied&quot;)
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param exceptionHandlingCustomizer the {@link Customizer} to provide more options for
	 *                                    the {@link ExceptionHandlingConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity exceptionHandling(Customizer<ExceptionHandlingConfigurer<HttpSecurity>> exceptionHandlingCustomizer) throws Exception {
		exceptionHandlingCustomizer.customize(getOrApply(new ExceptionHandlingConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Sets up management of the {@link SecurityContext} on the
	 * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is
	 * automatically applied when using {@link WebSecurityConfigurerAdapter}.
	 *
	 * @return the {@link SecurityContextConfigurer} for further customizations
	 * @throws Exception
	 */
	public SecurityContextConfigurer<HttpSecurity> securityContext() throws Exception {
		return getOrApply(new SecurityContextConfigurer<>());
	}

	/**
	 * Sets up management of the {@link SecurityContext} on the
	 * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is
	 * automatically applied when using {@link WebSecurityConfigurerAdapter}.
	 * <p>
	 * The following customization specifies the shared {@link SecurityContextRepository}
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class SecurityContextSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.securityContext(securityContext ->
	 * 				securityContext
	 * 					.securityContextRepository(SCR)
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param securityContextCustomizer the {@link Customizer} to provide more options for
	 *                                  the {@link SecurityContextConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity securityContext(Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer) throws Exception {
		securityContextCustomizer.customize(getOrApply(new SecurityContextConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Integrates the {@link HttpServletRequest} methods with the values found on the
	 * {@link SecurityContext}. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}.
	 *
	 * @return the {@link ServletApiConfigurer} for further customizations
	 * @throws Exception
	 */
	public ServletApiConfigurer<HttpSecurity> servletApi() throws Exception {
		return getOrApply(new ServletApiConfigurer<>());
	}

	/**
	 * Integrates the {@link HttpServletRequest} methods with the values found on the
	 * {@link SecurityContext}. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}. You can disable it using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ServletApiSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.servletApi(servletApi ->
	 * 				servletApi.disable()
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param servletApiCustomizer the {@link Customizer} to provide more options for
	 *                             the {@link ServletApiConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity servletApi(Customizer<ServletApiConfigurer<HttpSecurity>> servletApiCustomizer) throws Exception {
		servletApiCustomizer.customize(getOrApply(new ServletApiConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * 添加CSRF支持，默认
	 * Adds CSRF support. This is activated by default when using
	 * {@link WebSecurityConfigurerAdapter}'s default constructor. You can disable it
	 * using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .csrf().disable()
	 *             ...;
	 *     }
	 * }
	 * </pre>
	 *
	 * @return the {@link CsrfConfigurer} for further customizations
	 * @throws Exception
	 */
	public CsrfConfigurer<HttpSecurity> csrf() throws Exception {
		//获取应用上下文
		ApplicationContext context = getContext();
		return getOrApply(new CsrfConfigurer<>(context));
	}

	/**
	 * Adds CSRF support. This is activated by default when using
	 * {@link WebSecurityConfigurerAdapter}'s default constructor. You can disable it
	 * using:
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 *     protected void configure(HttpSecurity http) throws Exception {
	 *         http
	 *             .csrf(csrf -> csrf.disable());
	 *     }
	 * }
	 * </pre>
	 *
	 * @param csrfCustomizer the {@link Customizer} to provide more options for
	 *                       the {@link CsrfConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity csrf(Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer) throws Exception {
		ApplicationContext context = getContext();
		csrfCustomizer.customize(getOrApply(new CsrfConfigurer<>(context)));
		return HttpSecurity.this;
	}

	/**
	 * Provides logout support. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}. The default is that accessing the URL
	 * "/logout" will log the user out by invalidating the HTTP Session, cleaning up any
	 * {@link #rememberMe()} authentication that was configured, clearing the
	 * {@link SecurityContextHolder}, and then redirect to "/login?success".
	 *
	 * <h2>Example Custom Configuration</h2>
	 * <p>
	 * The following customization to log out when the URL "/custom-logout" is invoked.
	 * Log out will remove the cookie named "remove", not invalidate the HttpSession,
	 * clear the SecurityContextHolder, and upon completion redirect to "/logout-success".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.and()
	 * 				// sample logout customization
	 * 				.logout().deleteCookies(&quot;remove&quot;).invalidateHttpSession(false)
	 * 				.logoutUrl(&quot;/custom-logout&quot;).logoutSuccessUrl(&quot;/logout-success&quot;);
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link LogoutConfigurer} for further customizations
	 * @throws Exception
	 */
	public LogoutConfigurer<HttpSecurity> logout() throws Exception {
		return getOrApply(new LogoutConfigurer<>());
	}

	/**
	 * Provides logout support. This is automatically applied when using
	 * {@link WebSecurityConfigurerAdapter}. The default is that accessing the URL
	 * "/logout" will log the user out by invalidating the HTTP Session, cleaning up any
	 * {@link #rememberMe()} authentication that was configured, clearing the
	 * {@link SecurityContextHolder}, and then redirect to "/login?success".
	 *
	 * <h2>Example Custom Configuration</h2>
	 * <p>
	 * The following customization to log out when the URL "/custom-logout" is invoked.
	 * Log out will remove the cookie named "remove", not invalidate the HttpSession,
	 * clear the SecurityContextHolder, and upon completion redirect to "/logout-success".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample logout customization
	 * 			.logout(logout ->
	 * 				logout.deleteCookies(&quot;remove&quot;)
	 * 					.invalidateHttpSession(false)
	 * 					.logoutUrl(&quot;/custom-logout&quot;)
	 * 					.logoutSuccessUrl(&quot;/logout-success&quot;)
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param logoutCustomizer the {@link Customizer} to provide more options for
	 *                         the {@link LogoutConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity logout(Customizer<LogoutConfigurer<HttpSecurity>> logoutCustomizer) throws Exception {
		logoutCustomizer.customize(getOrApply(new LogoutConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Allows configuring how an anonymous user is represented. This is automatically
	 * applied when used in conjunction with {@link WebSecurityConfigurerAdapter}. By
	 * default anonymous users will be represented with an
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}
	 * and contain the role "ROLE_ANONYMOUS".
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration demonstrates how to specify that anonymous users should
	 * contain the role "ROLE_ANON" instead.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin()
	 * 				.and()
	 * 			// sample anonymous customization
	 * 			.anonymous().authorities(&quot;ROLE_ANON&quot;);
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The following demonstrates how to represent anonymous users as null. Note that this
	 * can cause {@link NullPointerException} in code that assumes anonymous
	 * authentication is enabled.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.formLogin()
	 * 				.and()
	 * 			// sample anonymous customization
	 * 			.anonymous().disable();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link AnonymousConfigurer} for further customizations
	 * @throws Exception
	 */
	public AnonymousConfigurer<HttpSecurity> anonymous() throws Exception {
		return getOrApply(new AnonymousConfigurer<>());
	}

	/**
	 * Allows configuring how an anonymous user is represented. This is automatically
	 * applied when used in conjunction with {@link WebSecurityConfigurerAdapter}. By
	 * default anonymous users will be represented with an
	 * {@link org.springframework.security.authentication.AnonymousAuthenticationToken}
	 * and contain the role "ROLE_ANONYMOUS".
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following configuration demonstrates how to specify that anonymous users should
	 * contain the role "ROLE_ANON" instead.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample anonymous customization
	 * 			.anonymous(anonymous ->
	 * 				anonymous
	 * 					.authorities(&quot;ROLE_ANON&quot;)
	 * 			)
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The following demonstrates how to represent anonymous users as null. Note that this
	 * can cause {@link NullPointerException} in code that assumes anonymous
	 * authentication is enabled.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class AnonymousSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			// sample anonymous customization
	 * 			.anonymous(anonymous ->
	 * 				anonymous.disable()
	 * 			);
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param anonymousCustomizer the {@link Customizer} to provide more options for
	 *                            the {@link AnonymousConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity anonymous(Customizer<AnonymousConfigurer<HttpSecurity>> anonymousCustomizer) throws Exception {
		anonymousCustomizer.customize(getOrApply(new AnonymousConfigurer<>()));
		return HttpSecurity.this;
	}


	/**
	 * 指定支持基于表单的身份验证. If
	 * 若果没有指定loginPage()这个配置，那么将使用默认的登录页面
	 *
	 * <h2>Example Configurations</h2>
	 * 默认的登录的URL为 /login
	 * <p>
	 * 作者：怪诞140819
	 * 链接：https://www.jianshu.com/p/6f1b129442a1
	 * 来源：简书
	 * 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
	 * Specifies to support form based authentication. If
	 * {@link FormLoginConfigurer#loginPage(String)} is not specified a default login page
	 * will be generated.
	 *
	 * <h2>Example Configurations</h2>
	 * <p>
	 * The most basic configuration defaults to automatically generating a login page at
	 * the URL "/login", redirecting to "/login?error" for authentication failure. The
	 * details of the login page can be found on
	 * {@link FormLoginConfigurer#loginPage(String)}
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The configuration below demonstrates customizing the defaults.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.usernameParameter(&quot;username&quot;) // default is username
	 * 				.passwordParameter(&quot;password&quot;) // default is password
	 * 				.loginPage(&quot;/authentication/login&quot;) // default is /login with an HTTP get
	 * 				.failureUrl(&quot;/authentication/login?failed&quot;) // default is /login?error
	 * 				.loginProcessingUrl(&quot;/authentication/login/process&quot;); // default is /login
	 * 																		// with an HTTP
	 * 																		// post
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link FormLoginConfigurer} for further customizations
	 * @throws Exception
	 * @see FormLoginConfigurer#loginPage(String)
	 */
	public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
		//T1这里的FormLoginConfigurer和getOrApply方法我们都不知道是啥玩意儿
		return getOrApply(new FormLoginConfigurer<>());
	}

	/**
	 * Specifies to support form based authentication. If
	 * {@link FormLoginConfigurer#loginPage(String)} is not specified a default login page
	 * will be generated.
	 *
	 * <h2>Example Configurations</h2>
	 * <p>
	 * The most basic configuration defaults to automatically generating a login page at
	 * the URL "/login", redirecting to "/login?error" for authentication failure. The
	 * details of the login page can be found on
	 * {@link FormLoginConfigurer#loginPage(String)}
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults());
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The configuration below demonstrates customizing the defaults.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(formLogin ->
	 * 				formLogin
	 * 					.usernameParameter(&quot;username&quot;)
	 * 					.passwordParameter(&quot;password&quot;)
	 * 					.loginPage(&quot;/authentication/login&quot;)
	 * 					.failureUrl(&quot;/authentication/login?failed&quot;)
	 * 					.loginProcessingUrl(&quot;/authentication/login/process&quot;)
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param formLoginCustomizer the {@link Customizer} to provide more options for
	 *                            the {@link FormLoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see FormLoginConfigurer#loginPage(String)
	 */
	public HttpSecurity formLogin(Customizer<FormLoginConfigurer<HttpSecurity>> formLoginCustomizer) throws Exception {
		formLoginCustomizer.customize(getOrApply(new FormLoginConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures authentication support using an SAML 2.0 Service Provider.
	 * <br>
	 * <br>
	 * <p>
	 * The &quot;authentication flow&quot; is implemented using the <b>Web Browser SSO Profile, using POST and REDIRECT bindings</b>,
	 * as documented in the <a target="_blank" href="https://docs.oasis-open.org/security/saml/">SAML V2.0 Core,Profiles and Bindings</a>
	 * specifications.
	 * <br>
	 * <br>
	 * <p>
	 * As a prerequisite to using this feature, is that you have a SAML v2.0 Identity Provider to provide an assertion.
	 * The representation of the Service Provider, the relying party, and the remote Identity Provider, the asserting party
	 * is contained within {@link RelyingPartyRegistration}.
	 * <br>
	 * <br>
	 * <p>
	 * {@link RelyingPartyRegistration}(s) are composed within a
	 * {@link RelyingPartyRegistrationRepository},
	 * which is <b>required</b> and must be registered with the {@link ApplicationContext} or
	 * configured via <code>saml2Login().relyingPartyRegistrationRepository(..)</code>.
	 * <br>
	 * <br>
	 * <p>
	 * The default configuration provides an auto-generated login page at <code>&quot;/login&quot;</code> and
	 * redirects to <code>&quot;/login?error&quot;</code> when an authentication error occurs.
	 * The login page will display each of the identity providers with a link
	 * that is capable of initiating the &quot;authentication flow&quot;.
	 * <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following example shows the minimal configuration required, using SimpleSamlPhp as the Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * public class Saml2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests()
	 * 					.anyRequest().authenticated()
	 * 					.and()
	 * 				  .saml2Login();
	 *        }
	 *    }
	 *
	 * 	&#064;Bean
	 * 	public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 * 		return new InMemoryRelyingPartyRegistrationRepository(this.getSaml2RelyingPartyRegistration());
	 *    }
	 *
	 * 	private RelyingPartyRegistration getSaml2RelyingPartyRegistration() {
	 * 		//remote IDP entity ID
	 * 		String idpEntityId = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
	 * 		//remote WebSSO Endpoint - Where to Send AuthNRequests to
	 * 		String webSsoEndpoint = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php";
	 * 		//local registration ID
	 * 		String registrationId = "simplesamlphp";
	 * 		//local entity ID - autogenerated based on URL
	 * 		String localEntityIdTemplate = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
	 * 		//local signing (and decryption key)
	 * 		Saml2X509Credential signingCredential = getSigningCredential();
	 * 		//IDP certificate for verification of incoming messages
	 * 		Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();
	 * 		return RelyingPartyRegistration.withRegistrationId(registrationId)
	 *  * 				.remoteIdpEntityId(idpEntityId)
	 *  * 				.idpWebSsoUrl(webSsoEndpoint)
	 *  * 				.credential(signingCredential)
	 *  * 				.credential(idpVerificationCertificate)
	 *  * 				.localEntityIdTemplate(localEntityIdTemplate)
	 *  * 				.build();
	 *    }
	 * }
	 * </pre>
	 *
	 * <p>
	 *
	 * @return the {@link Saml2LoginConfigurer} for further customizations
	 * @throws Exception
	 * @since 5.2
	 */
	public Saml2LoginConfigurer<HttpSecurity> saml2Login() throws Exception {
		return getOrApply(new Saml2LoginConfigurer<>());
	}

	/**
	 * Configures authentication support using an SAML 2.0 Service Provider.
	 * <br>
	 * <br>
	 * <p>
	 * The &quot;authentication flow&quot; is implemented using the <b>Web Browser SSO Profile, using POST and REDIRECT bindings</b>,
	 * as documented in the <a target="_blank" href="https://docs.oasis-open.org/security/saml/">SAML V2.0 Core,Profiles and Bindings</a>
	 * specifications.
	 * <br>
	 * <br>
	 * <p>
	 * As a prerequisite to using this feature, is that you have a SAML v2.0 Identity Provider to provide an assertion.
	 * The representation of the Service Provider, the relying party, and the remote Identity Provider, the asserting party
	 * is contained within {@link RelyingPartyRegistration}.
	 * <br>
	 * <br>
	 * <p>
	 * {@link RelyingPartyRegistration}(s) are composed within a
	 * {@link RelyingPartyRegistrationRepository},
	 * which is <b>required</b> and must be registered with the {@link ApplicationContext} or
	 * configured via <code>saml2Login().relyingPartyRegistrationRepository(..)</code>.
	 * <br>
	 * <br>
	 * <p>
	 * The default configuration provides an auto-generated login page at <code>&quot;/login&quot;</code> and
	 * redirects to <code>&quot;/login?error&quot;</code> when an authentication error occurs.
	 * The login page will display each of the identity providers with a link
	 * that is capable of initiating the &quot;authentication flow&quot;.
	 * <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following example shows the minimal configuration required, using SimpleSamlPhp as the Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * public class Saml2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests()
	 * 					.anyRequest().authenticated()
	 * 					.and()
	 * 				  .saml2Login(withDefaults());
	 *        }
	 *    }
	 *
	 * 	&#064;Bean
	 * 	public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
	 * 		return new InMemoryRelyingPartyRegistrationRepository(this.getSaml2RelyingPartyRegistration());
	 *    }
	 *
	 * 	private RelyingPartyRegistration getSaml2RelyingPartyRegistration() {
	 * 		//remote IDP entity ID
	 * 		String idpEntityId = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
	 * 		//remote WebSSO Endpoint - Where to Send AuthNRequests to
	 * 		String webSsoEndpoint = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php";
	 * 		//local registration ID
	 * 		String registrationId = "simplesamlphp";
	 * 		//local entity ID - autogenerated based on URL
	 * 		String localEntityIdTemplate = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
	 * 		//local signing (and decryption key)
	 * 		Saml2X509Credential signingCredential = getSigningCredential();
	 * 		//IDP certificate for verification of incoming messages
	 * 		Saml2X509Credential idpVerificationCertificate = getVerificationCertificate();
	 * 		return RelyingPartyRegistration.withRegistrationId(registrationId)
	 *  * 				.remoteIdpEntityId(idpEntityId)
	 *  * 				.idpWebSsoUrl(webSsoEndpoint)
	 *  * 				.credential(signingCredential)
	 *  * 				.credential(idpVerificationCertificate)
	 *  * 				.localEntityIdTemplate(localEntityIdTemplate)
	 *  * 				.build();
	 *    }
	 * }
	 * </pre>
	 *
	 * <p>
	 *
	 * @param saml2LoginCustomizer the {@link Customizer} to provide more options for
	 *                             the {@link Saml2LoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @since 5.2
	 */
	public HttpSecurity saml2Login(Customizer<Saml2LoginConfigurer<HttpSecurity>> saml2LoginCustomizer) throws Exception {
		saml2LoginCustomizer.customize(getOrApply(new Saml2LoginConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0 Provider.
	 * <br>
	 * <br>
	 * <p>
	 * The &quot;authentication flow&quot; is implemented using the <b>Authorization Code Grant</b>, as specified in the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">OAuth 2.0 Authorization Framework</a>
	 * and <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">OpenID Connect Core 1.0</a>
	 * specification.
	 * <br>
	 * <br>
	 * <p>
	 * As a prerequisite to using this feature, you must register a client with a provider.
	 * The client registration information may than be used for configuring
	 * a {@link org.springframework.security.oauth2.client.registration.ClientRegistration} using a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.Builder}.
	 * <br>
	 * <br>
	 * <p>
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration}(s) are composed within a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistrationRepository},
	 * which is <b>required</b> and must be registered with the {@link ApplicationContext} or
	 * configured via <code>oauth2Login().clientRegistrationRepository(..)</code>.
	 * <br>
	 * <br>
	 * <p>
	 * The default configuration provides an auto-generated login page at <code>&quot;/login&quot;</code> and
	 * redirects to <code>&quot;/login?error&quot;</code> when an authentication error occurs.
	 * The login page will display each of the clients with a link
	 * that is capable of initiating the &quot;authentication flow&quot;.
	 * <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following example shows the minimal configuration required, using Google as the Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * public class OAuth2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests()
	 * 					.anyRequest().authenticated()
	 * 					.and()
	 * 				  .oauth2Login();
	 *        }
	 *    }
	 *
	 * 	&#064;Bean
	 * 	public ClientRegistrationRepository clientRegistrationRepository() {
	 * 		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	 *    }
	 *
	 * 	private ClientRegistration googleClientRegistration() {
	 * 		return ClientRegistration.withRegistrationId("google")
	 * 			.clientId("google-client-id")
	 * 			.clientSecret("google-client-secret")
	 * 			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
	 * 			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * 			.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
	 * 			.scope("openid", "profile", "email", "address", "phone")
	 * 			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
	 * 			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
	 * 			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
	 * 			.userNameAttributeName(IdTokenClaimNames.SUB)
	 * 			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
	 * 			.clientName("Google")
	 * 			.build();
	 *    }
	 * }
	 * </pre>
	 *
	 * <p>
	 * For more advanced configuration, see {@link OAuth2LoginConfigurer} for available options to customize the defaults.
	 *
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
	 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1 Authorization Code Flow</a>
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistration
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
	 * @since 5.0
	 */
	public OAuth2LoginConfigurer<HttpSecurity> oauth2Login() throws Exception {
		return getOrApply(new OAuth2LoginConfigurer<>());
	}

	/**
	 * Configures authentication support using an OAuth 2.0 and/or OpenID Connect 1.0 Provider.
	 * <br>
	 * <br>
	 * <p>
	 * The &quot;authentication flow&quot; is implemented using the <b>Authorization Code Grant</b>, as specified in the
	 * <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">OAuth 2.0 Authorization Framework</a>
	 * and <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">OpenID Connect Core 1.0</a>
	 * specification.
	 * <br>
	 * <br>
	 * <p>
	 * As a prerequisite to using this feature, you must register a client with a provider.
	 * The client registration information may than be used for configuring
	 * a {@link org.springframework.security.oauth2.client.registration.ClientRegistration} using a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.Builder}.
	 * <br>
	 * <br>
	 * <p>
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration}(s) are composed within a
	 * {@link org.springframework.security.oauth2.client.registration.ClientRegistrationRepository},
	 * which is <b>required</b> and must be registered with the {@link ApplicationContext} or
	 * configured via <code>oauth2Login().clientRegistrationRepository(..)</code>.
	 * <br>
	 * <br>
	 * <p>
	 * The default configuration provides an auto-generated login page at <code>&quot;/login&quot;</code> and
	 * redirects to <code>&quot;/login?error&quot;</code> when an authentication error occurs.
	 * The login page will display each of the clients with a link
	 * that is capable of initiating the &quot;authentication flow&quot;.
	 * <br>
	 * <br>
	 *
	 * <p>
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following example shows the minimal configuration required, using Google as the Authentication Provider.
	 *
	 * <pre>
	 * &#064;Configuration
	 * public class OAuth2LoginConfig {
	 *
	 * 	&#064;EnableWebSecurity
	 * 	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 		&#064;Override
	 * 		protected void configure(HttpSecurity http) throws Exception {
	 * 			http
	 * 				.authorizeRequests(authorizeRequests ->
	 * 					authorizeRequests
	 * 						.anyRequest().authenticated()
	 * 				)
	 * 				.oauth2Login(withDefaults());
	 *        }
	 *    }
	 *
	 * 	&#064;Bean
	 * 	public ClientRegistrationRepository clientRegistrationRepository() {
	 * 		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	 *    }
	 *
	 * 	private ClientRegistration googleClientRegistration() {
	 * 		return ClientRegistration.withRegistrationId("google")
	 * 			.clientId("google-client-id")
	 * 			.clientSecret("google-client-secret")
	 * 			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
	 * 			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * 			.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
	 * 			.scope("openid", "profile", "email", "address", "phone")
	 * 			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
	 * 			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
	 * 			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
	 * 			.userNameAttributeName(IdTokenClaimNames.SUB)
	 * 			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
	 * 			.clientName("Google")
	 * 			.build();
	 *    }
	 * }
	 * </pre>
	 *
	 * <p>
	 * For more advanced configuration, see {@link OAuth2LoginConfigurer} for available options to customize the defaults.
	 *
	 * @param oauth2LoginCustomizer the {@link Customizer} to provide more options for
	 *                              the {@link OAuth2LoginConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
	 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1 Authorization Code Flow</a>
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistration
	 * @see org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
	 */
	public HttpSecurity oauth2Login(Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer) throws Exception {
		oauth2LoginCustomizer.customize(getOrApply(new OAuth2LoginConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures OAuth 2.0 Client support.
	 *
	 * @return the {@link OAuth2ClientConfigurer} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization Framework</a>
	 * @since 5.1
	 */
	public OAuth2ClientConfigurer<HttpSecurity> oauth2Client() throws Exception {
		OAuth2ClientConfigurer<HttpSecurity> configurer = getOrApply(new OAuth2ClientConfigurer<>());
		this.postProcess(configurer);
		return configurer;
	}

	/**
	 * Configures OAuth 2.0 Client support.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following example demonstrates how to enable OAuth 2.0 Client support for all endpoints.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.oauth2Client(withDefaults());
	 *    }
	 * }
	 * </pre>
	 *
	 * @param oauth2ClientCustomizer the {@link Customizer} to provide more options for
	 *                               the {@link OAuth2ClientConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization Framework</a>
	 */
	public HttpSecurity oauth2Client(Customizer<OAuth2ClientConfigurer<HttpSecurity>> oauth2ClientCustomizer) throws Exception {
		oauth2ClientCustomizer.customize(getOrApply(new OAuth2ClientConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * Configures OAuth 2.0 Resource Server support.
	 *
	 * @return the {@link OAuth2ResourceServerConfigurer} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization Framework</a>
	 * @since 5.1
	 */
	public OAuth2ResourceServerConfigurer<HttpSecurity> oauth2ResourceServer() throws Exception {
		OAuth2ResourceServerConfigurer<HttpSecurity> configurer = getOrApply(new OAuth2ResourceServerConfigurer<>(getContext()));
		this.postProcess(configurer);
		return configurer;
	}

	/**
	 * Configures OAuth 2.0 Resource Server support.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The following example demonstrates how to configure a custom JWT authentication converter.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.anyRequest().authenticated()
	 * 			)
	 * 			.oauth2ResourceServer(oauth2ResourceServer ->
	 * 				oauth2ResourceServer
	 * 					.jwt(jwt ->
	 * 						jwt
	 * 							.jwtAuthenticationConverter(jwtDecoder())
	 * 					)
	 * 			);
	 *    }
	 *
	 * 	&#064;Bean
	 * 	public JwtDecoder jwtDecoder() {
	 * 		return JwtDecoders.fromOidcIssuerLocation(issuerUri);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param oauth2ResourceServerCustomizer the {@link Customizer} to provide more options for
	 *                                       the {@link OAuth2ResourceServerConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.1">OAuth 2.0 Authorization Framework</a>
	 */
	public HttpSecurity oauth2ResourceServer(Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer)
			throws Exception {
		OAuth2ResourceServerConfigurer<HttpSecurity> configurer = getOrApply(new OAuth2ResourceServerConfigurer<>(getContext()));
		this.postProcess(configurer);
		oauth2ResourceServerCustomizer.customize(configurer);
		return HttpSecurity.this;
	}

	/**
	 * Configures channel security. In order for this configuration to be useful at least
	 * one mapping to a required channel must be provided.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The example below demonstrates how to require HTTPs for every request. Only
	 * requiring HTTPS for some requests is supported, but not recommended since an
	 * application that allows for HTTP introduces many security vulnerabilities. For one
	 * such example, read about <a
	 * href="https://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().formLogin()
	 * 				.and().requiresChannel().anyRequest().requiresSecure();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link ChannelSecurityConfigurer} for further customizations
	 * @throws Exception
	 */
	public ChannelSecurityConfigurer<HttpSecurity>.ChannelRequestMatcherRegistry requiresChannel()
			throws Exception {
		ApplicationContext context = getContext();
		return getOrApply(new ChannelSecurityConfigurer<>(context))
				.getRegistry();
	}

	/**
	 * Configures channel security. In order for this configuration to be useful at least
	 * one mapping to a required channel must be provided.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The example below demonstrates how to require HTTPs for every request. Only
	 * requiring HTTPS for some requests is supported, but not recommended since an
	 * application that allows for HTTP introduces many security vulnerabilities. For one
	 * such example, read about <a
	 * href="https://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.formLogin(withDefaults())
	 * 			.requiresChannel(requiresChannel ->
	 * 				requiresChannel
	 * 					.anyRequest().requiresSecure()
	 * 			);
	 *    }
	 * }
	 * </pre>
	 *
	 * @param requiresChannelCustomizer the {@link Customizer} to provide more options for
	 *                                  the {@link ChannelSecurityConfigurer.ChannelRequestMatcherRegistry}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity requiresChannel(Customizer<ChannelSecurityConfigurer<HttpSecurity>.ChannelRequestMatcherRegistry> requiresChannelCustomizer)
			throws Exception {
		ApplicationContext context = getContext();
		requiresChannelCustomizer.customize(getOrApply(new ChannelSecurityConfigurer<>(context))
				.getRegistry());
		return HttpSecurity.this;
	}

	/**
	 * 配置Http Basic的认证方式
	 * <p>
	 * 下面的示例演示如何为应用程序配置HTTP基本身份验证。默认领域是“realm”，但可以 自定义
	 * Configures HTTP Basic authentication.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The example below demonstrates how to configure HTTP Basic authentication for an
	 * application. The default realm is "Realm", but can be
	 * customized using {@link HttpBasicConfigurer#realmName(String)}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http.authorizeRequests().antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and().httpBasic();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link HttpBasicConfigurer} for further customizations
	 * @throws Exception
	 */
	public HttpBasicConfigurer<HttpSecurity> httpBasic() throws Exception {
		return getOrApply(new HttpBasicConfigurer<>());
	}

	/**
	 * Configures HTTP Basic authentication.
	 *
	 * <h2>Example Configuration</h2>
	 * <p>
	 * The example below demonstrates how to configure HTTP Basic authentication for an
	 * application. The default realm is "Realm", but can be
	 * customized using {@link HttpBasicConfigurer#realmName(String)}.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 *    }
	 * }
	 * </pre>
	 *
	 * @param httpBasicCustomizer the {@link Customizer} to provide more options for
	 *                            the {@link HttpBasicConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 * @throws Exception
	 */
	public HttpSecurity httpBasic(Customizer<HttpBasicConfigurer<HttpSecurity>> httpBasicCustomizer) throws Exception {
		httpBasicCustomizer.customize(getOrApply(new HttpBasicConfigurer<>()));
		return HttpSecurity.this;
	}

	/**
	 * 设置共享实例
	 *
	 * @param sharedType the Class to key the shared object by.
	 * @param object     the Object to store
	 * @param <C>
	 */
	public <C> void setSharedObject(Class<C> sharedType, C object) {
		super.setSharedObject(sharedType, object);
	}

	@Override
	protected void beforeConfigure() throws Exception {
		setSharedObject(AuthenticationManager.class, getAuthenticationRegistry().build());
	}

	/**
	 * @return
	 */
	@Override
	protected DefaultSecurityFilterChain performBuild() {
		//对filter进行排序
		filters.sort(comparator);
		return new DefaultSecurityFilterChain(requestMatcher, filters);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.config.annotation.web.HttpSecurityBuilder#authenticationProvider
	 * (org.springframework.security.authentication.AuthenticationProvider)
	 */
	public HttpSecurity authenticationProvider(
			AuthenticationProvider authenticationProvider) {
		getAuthenticationRegistry().authenticationProvider(authenticationProvider);
		return this;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.config.annotation.web.HttpSecurityBuilder#userDetailsService
	 * (org.springframework.security.core.userdetails.UserDetailsService)
	 */
	public HttpSecurity userDetailsService(UserDetailsService userDetailsService)
			throws Exception {
		getAuthenticationRegistry().userDetailsService(userDetailsService);
		return this;
	}

	private AuthenticationManagerBuilder getAuthenticationRegistry() {
		return getSharedObject(AuthenticationManagerBuilder.class);
	}

	/*
	在指定的filter后添加filter
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.config.annotation.web.HttpSecurityBuilder#addFilterAfter(javax
	 * .servlet.Filter, java.lang.Class)
	 */
	public HttpSecurity addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
		comparator.registerAfter(filter.getClass(), afterFilter);
		return addFilter(filter);
	}

	/*
	 * (non-Javadoc)
	 *filters的list 只是通过addFilter()方法添加进来
	 * @see
	 * org.springframework.security.config.annotation.web.HttpSecurityBuilder#addFilterBefore(
	 * javax.servlet.Filter, java.lang.Class)
	 */
	public HttpSecurity addFilterBefore(Filter filter,
			Class<? extends Filter> beforeFilter) {
		comparator.registerBefore(filter.getClass(), beforeFilter);
		return addFilter(filter);
	}

	/*
	添加Filter
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.security.config.annotation.web.HttpSecurityBuilder#addFilter(javax.
	 * servlet.Filter)
	 */
	public HttpSecurity addFilter(Filter filter) {
		Class<? extends Filter> filterClass = filter.getClass();
		if (!comparator.isRegistered(filterClass)) {
			throw new IllegalArgumentException(
					"The Filter class "
							+ filterClass.getName()
							+ " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
		}
		this.filters.add(filter);
		return this;
	}

	/**
	 * 在同一位置注册多个过滤器意味着它们的顺序不是确定性的。更具体地说，在同一位置注册多个过滤器不会覆盖现有的过滤器
	 * Adds the Filter at the location of the specified Filter class. For example, if you
	 * want the filter CustomFilter to be registered in the same position as
	 * {@link UsernamePasswordAuthenticationFilter}, you can invoke:
	 *
	 * <pre>
	 * addFilterAt(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
	 * </pre>
	 * <p>
	 * Registration of multiple Filters in the same location means their ordering is not
	 * deterministic. More concretely, registering multiple Filters in the same location
	 * does not override existing Filters. Instead, do not register Filters you do not
	 * want to use.
	 *
	 * @param filter   the Filter to register
	 * @param atFilter the location of another {@link Filter} that is already registered
	 *                 (i.e. known) with Spring Security.
	 * @return the {@link HttpSecurity} for further customizations
	 */
	public HttpSecurity addFilterAt(Filter filter, Class<? extends Filter> atFilter) {
		this.comparator.registerAt(filter.getClass(), atFilter);
		return addFilter(filter);
	}

	/**
	 * Allows specifying which {@link HttpServletRequest} instances this
	 * {@link HttpSecurity} will be invoked on. This method allows for easily invoking the
	 * {@link HttpSecurity} for multiple different {@link RequestMatcher} instances. If
	 * only a single {@link RequestMatcher} is necessary consider using {@link #mvcMatcher(String)},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, or
	 * {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #requestMatchers()} will not override previous invocations of {@link #mvcMatcher(String)}},
	 * {@link #requestMatchers()}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * <h3>Example Configurations</h3>
	 * <p>
	 * The following configuration enables the {@link HttpSecurity} for URLs that begin
	 * with "/api/" or "/oauth/".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers()
	 * 				.antMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
	 * 				.and()
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.httpBasic();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth
	 * 			.inMemoryAuthentication()
	 * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The configuration below is the same as the previous configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers()
	 * 				.antMatchers(&quot;/api/**&quot;)
	 * 				.antMatchers(&quot;/oauth/**&quot;)
	 * 				.and()
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.httpBasic();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth
	 * 			.inMemoryAuthentication()
	 * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The configuration below is also the same as the above configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers()
	 * 				.antMatchers(&quot;/api/**&quot;)
	 * 				.and()
	 * 			 .requestMatchers()
	 * 				.antMatchers(&quot;/oauth/**&quot;)
	 * 				.and()
	 * 			.authorizeRequests()
	 * 				.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 				.and()
	 * 			.httpBasic();
	 *    }
	 *
	 * 	&#064;Override
	 * 	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 * 		auth
	 * 			.inMemoryAuthentication()
	 * 				.withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;);
	 *    }
	 * }
	 * </pre>
	 *
	 * @return the {@link RequestMatcherConfigurer} for further customizations
	 */
	public RequestMatcherConfigurer requestMatchers() {
		return requestMatcherConfigurer;
	}

	/**
	 * Allows specifying which {@link HttpServletRequest} instances this
	 * {@link HttpSecurity} will be invoked on. This method allows for easily invoking the
	 * {@link HttpSecurity} for multiple different {@link RequestMatcher} instances. If
	 * only a single {@link RequestMatcher} is necessary consider using {@link #mvcMatcher(String)},
	 * {@link #antMatcher(String)}, {@link #regexMatcher(String)}, or
	 * {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #requestMatchers()} will not override previous invocations of {@link #mvcMatcher(String)}},
	 * {@link #requestMatchers()}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * <h3>Example Configurations</h3>
	 * <p>
	 * The following configuration enables the {@link HttpSecurity} for URLs that begin
	 * with "/api/" or "/oauth/".
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers(requestMatchers ->
	 * 				requestMatchers
	 * 					.antMatchers(&quot;/api/**&quot;, &quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The configuration below is the same as the previous configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers(requestMatchers ->
	 * 				requestMatchers
	 * 					.antMatchers(&quot;/api/**&quot;)
	 * 					.antMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 *    }
	 * }
	 * </pre>
	 * <p>
	 * The configuration below is also the same as the above configuration.
	 *
	 * <pre>
	 * &#064;Configuration
	 * &#064;EnableWebSecurity
	 * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
	 *
	 * 	&#064;Override
	 * 	protected void configure(HttpSecurity http) throws Exception {
	 * 		http
	 * 			.requestMatchers(requestMatchers ->
	 * 				requestMatchers
	 * 					.antMatchers(&quot;/api/**&quot;)
	 * 			)
	 * 			.requestMatchers(requestMatchers ->
	 * 			requestMatchers
	 * 				.antMatchers(&quot;/oauth/**&quot;)
	 * 			)
	 * 			.authorizeRequests(authorizeRequests ->
	 * 				authorizeRequests
	 * 					.antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
	 * 			)
	 * 			.httpBasic(withDefaults());
	 *    }
	 * }
	 * </pre>
	 *
	 * @param requestMatcherCustomizer the {@link Customizer} to provide more options for
	 *                                 the {@link RequestMatcherConfigurer}
	 * @return the {@link HttpSecurity} for further customizations
	 */
	public HttpSecurity requestMatchers(Customizer<RequestMatcherConfigurer> requestMatcherCustomizer) {
		requestMatcherCustomizer.customize(requestMatcherConfigurer);
		return HttpSecurity.this;
	}

	/**
	 * 允许将{@link HttpSecurity}配置为仅在匹配提供的{@link RequestMatcher}时调用。如果需要更高级的配置，可以考虑使用{@link#requestMatchers（）}。
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided {@link RequestMatcher}. If more advanced configuration is necessary,
	 * consider using {@link #requestMatchers()}.
	 *
	 * <p>
	 * Invoking {@link #requestMatcher(RequestMatcher)} will override previous invocations
	 * of {@link #requestMatchers()}, {@link #mvcMatcher(String)}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * @param requestMatcher the {@link RequestMatcher} to use (i.e. new
	 *                       AntPathRequestMatcher("/admin/**","GET") )
	 * @return the {@link HttpSecurity} for further customizations
	 * @see #requestMatchers()
	 * @see #antMatcher(String)
	 * @see #regexMatcher(String)
	 */
	public HttpSecurity requestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
		return this;
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided ant pattern. If more advanced configuration is necessary, consider using
	 * {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #antMatcher(String)} will override previous invocations of {@link #mvcMatcher(String)}},
	 * {@link #requestMatchers()}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * @param antPattern the Ant Pattern to match on (i.e. "/admin/**")
	 * @return the {@link HttpSecurity} for further customizations
	 * @see AntPathRequestMatcher
	 */
	public HttpSecurity antMatcher(String antPattern) {
		return requestMatcher(new AntPathRequestMatcher(antPattern));
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided Spring MVC pattern. If more advanced configuration is necessary, consider using
	 * {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #mvcMatcher(String)} will override previous invocations of {@link #mvcMatcher(String)}},
	 * {@link #requestMatchers()}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * @param mvcPattern the Spring MVC Pattern to match on (i.e. "/admin/**")
	 * @return the {@link HttpSecurity} for further customizations
	 * @see MvcRequestMatcher
	 */
	public HttpSecurity mvcMatcher(String mvcPattern) {
		HandlerMappingIntrospector introspector = new HandlerMappingIntrospector(getContext());
		return requestMatcher(new MvcRequestMatcher(introspector, mvcPattern));
	}

	/**
	 * Allows configuring the {@link HttpSecurity} to only be invoked when matching the
	 * provided regex pattern. If more advanced configuration is necessary, consider using
	 * {@link #requestMatchers()} or {@link #requestMatcher(RequestMatcher)}.
	 *
	 * <p>
	 * Invoking {@link #regexMatcher(String)} will override previous invocations of {@link #mvcMatcher(String)}},
	 * {@link #requestMatchers()}, {@link #antMatcher(String)},
	 * {@link #regexMatcher(String)}, and {@link #requestMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * @param pattern the Regular Expression to match on (i.e. "/admin/.+")
	 * @return the {@link HttpSecurity} for further customizations
	 * @see RegexRequestMatcher
	 */
	public HttpSecurity regexMatcher(String pattern) {
		return requestMatcher(new RegexRequestMatcher(pattern, null));
	}

	/**
	 * An extension to {@link RequestMatcherConfigurer} that allows optionally configuring
	 * the servlet path.
	 *
	 * @author Rob Winch
	 */
	public final class MvcMatchersRequestMatcherConfigurer extends RequestMatcherConfigurer {

		/**
		 * Creates a new instance
		 *
		 * @param context  the {@link ApplicationContext} to use
		 * @param matchers the {@link MvcRequestMatcher} instances to set the servlet path
		 *                 on if {@link #servletPath(String)} is set.
		 */
		private MvcMatchersRequestMatcherConfigurer(ApplicationContext context,
				List<MvcRequestMatcher> matchers) {
			super(context);
			this.matchers = new ArrayList<>(matchers);
		}

		public RequestMatcherConfigurer servletPath(String servletPath) {
			for (RequestMatcher matcher : this.matchers) {
				((MvcRequestMatcher) matcher).setServletPath(servletPath);
			}
			return this;
		}

	}

	/**
	 * Allows mapping HTTP requests that this {@link HttpSecurity} will be used for
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	public class RequestMatcherConfigurer
			extends AbstractRequestMatcherRegistry<RequestMatcherConfigurer> {

		protected List<RequestMatcher> matchers = new ArrayList<>();

		/**
		 * @param context
		 */
		private RequestMatcherConfigurer(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		public MvcMatchersRequestMatcherConfigurer mvcMatchers(HttpMethod method,
				String... mvcPatterns) {
			List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
			setMatchers(mvcMatchers);
			return new MvcMatchersRequestMatcherConfigurer(getContext(), mvcMatchers);
		}

		@Override
		public MvcMatchersRequestMatcherConfigurer mvcMatchers(String... patterns) {
			return mvcMatchers(null, patterns);
		}

		/**
		 * @param requestMatchers the {@link RequestMatcher} instances that were created
		 * @return
		 */
		@Override
		protected RequestMatcherConfigurer chainRequestMatchers(
				List<RequestMatcher> requestMatchers) {
			setMatchers(requestMatchers);
			return this;
		}

		private void setMatchers(List<? extends RequestMatcher> requestMatchers) {
			this.matchers.addAll(requestMatchers);
			requestMatcher(new OrRequestMatcher(this.matchers));
		}

		/**
		 * Return the {@link HttpSecurity} for further customizations
		 *
		 * @return the {@link HttpSecurity} for further customizations
		 */
		public HttpSecurity and() {
			return HttpSecurity.this;
		}

	}

	/**
	 * 如果存在则获取，否则进行新建
	 * If the {@link SecurityConfigurer} has already been specified get the original,
	 * otherwise apply the new {@link SecurityConfigurerAdapter}.
	 *
	 * @param configurer the {@link SecurityConfigurer} to apply if one is not found for
	 *                   this {@link SecurityConfigurer} class.
	 * @return the current {@link SecurityConfigurer} for the configurer passed in
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> C getOrApply(
			C configurer) throws Exception {
		//T2 这里的意思是去查看是否有存在了
		C existingConfig = (C) getConfigurer(configurer.getClass());
		if (existingConfig != null) {
			return existingConfig;
		}
		//T3 不存在的情况下就去调用apply()这个方法
		return apply(configurer);
	}
}
