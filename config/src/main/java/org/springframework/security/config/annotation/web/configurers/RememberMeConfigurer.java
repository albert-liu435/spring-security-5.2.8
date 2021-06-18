/*
 * Copyright 2002-2015 the original author or authors.
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

import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

/**
 * https://andyboke.blog.csdn.net/article/details/94402246
 * <p>
 * 作为一个配置HttpSecurity的SecurityConfigurer,RememberMeConfigurer的配置任务如下 :
 * <p>
 * 使用同一个key
 * 缺省情况下，外界不指定该key ,该key使用缺省值UUID随机字符串
 * <p>
 * 为安全配置器HttpSecurity配置如下安全过滤器Filter
 * RememberMeAuthenticationFilter
 * 属性authenticationManager使用安全配置器HttpSecurity共享对象AuthenticationManager
 * 属性rememberMeServices 来自
 * 使用到了key ,用于Remember-Me用户登录生成RememberMeAuthenticationToken
 * <p>
 * 外部设置的RememberMeServices对象
 * 或者缺省创建的RememberMeServices对象
 * 为安全配置器HttpSecurity提供一个AuthenticationProvider
 * RememberMeAuthenticationProvider
 * 该AuthenticationProvider会被添加到安全配置器HttpSecurity的共享对象AuthenticationManager中
 * 使用到了key,用于认证Remember-Me用户登录成功生成的RememberMeAuthenticationToken
 * 外部不指定RememberMeServices时，缺省RememberMeServices的创建过程如下 :
 * <p>
 * 如果外部设定了 tokenRepository, 则创建的是一个 PersistentTokenBasedRememberMeServices 对象;
 * 如果外部没有设定 tokenRepository, 则创建的是一个 TokenBasedRememberMeServices 对象;
 * 缺省情况下,RememberMeConfigurer的属性rememberMeServices,tokenRepository都未设置。所以缺省使用的RememberMeServices会是一个自己创建的TokenBasedRememberMeServices。
 * <p>
 * 配置记住我身份验证
 * 这通常包括用户在输入用户名和密码时选中一个框，该框表示“记住我”。
 * Configures Remember Me authentication. This typically involves the user checking a box
 * when they enter their username and password that states to "Remember Me".
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link RememberMeAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * The following shared objects are populated
 *
 * <ul>
 * <li>
 * {@link HttpSecurity#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)}
 * is populated with a {@link RememberMeAuthenticationProvider}</li>
 * <li>{@link RememberMeServices} is populated as a shared object and available on
 * {@link HttpSecurity#getSharedObject(Class)}</li>
 * <li>{@link LogoutConfigurer#addLogoutHandler(LogoutHandler)} is used to add a logout
 * handler to clean up the remember me authentication.</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 * <p>
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link AuthenticationManager}</li>
 * <li>{@link UserDetailsService} if no {@link #userDetailsService(UserDetailsService)}
 * was specified.</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if present will be populated with
 * information from the configuration</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 3.2
 */
public final class RememberMeConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<RememberMeConfigurer<H>, H> {
	/**
	 * 默认的remember-me默认名称
	 * The default name for remember me parameter name and remember me cookie name
	 */
	private static final String DEFAULT_REMEMBER_ME_NAME = "remember-me";
	//处理验证成功的逻辑
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	//存入session中的key值
	private String key;
	//记住我操作的service
	private RememberMeServices rememberMeServices;
	//登录退出处理器
	private LogoutHandler logoutHandler;
	//
	private String rememberMeParameter = DEFAULT_REMEMBER_ME_NAME;
	private String rememberMeCookieName = DEFAULT_REMEMBER_ME_NAME;

	private String rememberMeCookieDomain;
	private PersistentTokenRepository tokenRepository;

	private UserDetailsService userDetailsService;
	//设置token的有效期
	private Integer tokenValiditySeconds;
	private Boolean useSecureCookie;
	//Remeber的默认值
	private Boolean alwaysRemember;

	/**
	 * Creates a new instance
	 */
	public RememberMeConfigurer() {
	}

	/**
	 * 设置 Remember-Me 认证令牌的有效时长，单位:秒
	 * Allows specifying how long (in seconds) a token is valid for
	 *
	 * @param tokenValiditySeconds
	 * @return {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setTokenValiditySeconds(int)
	 */
	public RememberMeConfigurer<H> tokenValiditySeconds(int tokenValiditySeconds) {
		this.tokenValiditySeconds = tokenValiditySeconds;
		return this;
	}

	/**
	 * Remember-Me cookie 是否需要被标记为安全cookie。安全cookie只能通过HTTPS连接传输，
	 * 不能通过 HTTP 连接传输以避免它们被拦截。
	 * 缺省情况下如果请求是安全的，cookie也是安全的。如果你只想在HTTPS中使用remember-me(推荐方案),
	 * 你应该将此标志设置为 true
	 * Whether the cookie should be flagged as secure or not. Secure cookies can only be
	 * sent over an HTTPS connection and thus cannot be accidentally submitted over HTTP
	 * where they could be intercepted.
	 * <p>
	 * By default the cookie will be secure if the request is secure. If you only want to
	 * use remember-me over HTTPS (recommended) you should set this property to
	 * {@code true}.
	 *
	 * @param useSecureCookie set to {@code true} to always user secure cookies,
	 *                        {@code false} to disable their use.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setUseSecureCookie(boolean)
	 */
	public RememberMeConfigurer<H> useSecureCookie(boolean useSecureCookie) {
		this.useSecureCookie = useSecureCookie;
		return this;
	}

	/**
	 * 设置查询 UserDetails 属性需要使用的 UserDetailsService。
	 * 缺省情况下使用 HttpSecurity 安全对象池中的 UserDetailsService
	 * (WebSecurityConfigurerAdapter#configure(AuthenticationManagerBuilder)配置时设置)，
	 * 不过用户可以通过该方法指定一个其他的 UserDetailsService
	 * Specifies the {@link UserDetailsService} used to look up the {@link UserDetails}
	 * when a remember me token is valid. The default is to use the
	 * {@link UserDetailsService} found by invoking
	 * {@link HttpSecurity#getSharedObject(Class)} which is set when using
	 * {@link WebSecurityConfigurerAdapter#configure(AuthenticationManagerBuilder)}.
	 * Alternatively, one can populate {@link #rememberMeServices(RememberMeServices)}.
	 *
	 * @param userDetailsService the {@link UserDetailsService} to configure
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices
	 */
	public RememberMeConfigurer<H> userDetailsService(
			UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
		return this;
	}

	/**
	 * 指定要使用的 PersistentTokenRepository， 缺省使用的 PersistentTokenRepository
	 * Specifies the {@link PersistentTokenRepository} to use. The default is to use
	 * {@link TokenBasedRememberMeServices} instead.
	 *
	 * @param tokenRepository the {@link PersistentTokenRepository} to use
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> tokenRepository(
			PersistentTokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
		return this;
	}

	/**
	 * 设置用于标识为“记住我”身份验证创建的令牌的密钥。默认值是随机生成的安全密钥。
	 * Sets the key to identify tokens created for remember me authentication. Default is
	 * a secure randomly generated key.
	 * If {@link #rememberMeServices(RememberMeServices)} is specified and is of type
	 * {@link AbstractRememberMeServices}, then the default is the key set in
	 * {@link AbstractRememberMeServices}.
	 *
	 * @param key the key to identify tokens created for remember me authentication
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> key(String key) {
		this.key = key;
		return this;
	}

	/**
	 * The HTTP parameter used to indicate to remember the user at time of login.
	 *
	 * @param rememberMeParameter the HTTP parameter used to indicate to remember the user
	 * @return the {@link RememberMeConfigurer} for further customization
	 */
	public RememberMeConfigurer<H> rememberMeParameter(String rememberMeParameter) {
		this.rememberMeParameter = rememberMeParameter;
		return this;
	}

	/**
	 * The name of cookie which store the token for remember me authentication. Defaults
	 * to 'remember-me'.
	 *
	 * @param rememberMeCookieName the name of cookie which store the token for remember
	 *                             me authentication
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @since 4.0.1
	 */
	public RememberMeConfigurer<H> rememberMeCookieName(String rememberMeCookieName) {
		this.rememberMeCookieName = rememberMeCookieName;
		return this;
	}

	/**
	 * The domain name within which the remember me cookie is visible.
	 *
	 * @param rememberMeCookieDomain the domain name within which the remember me cookie
	 *                               is visible.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @since 4.1.0
	 */
	public RememberMeConfigurer<H> rememberMeCookieDomain(String rememberMeCookieDomain) {
		this.rememberMeCookieDomain = rememberMeCookieDomain;
		return this;
	}

	/**
	 * 设置被记忆的用户 Remember-Me 认证通过时的认证处理器。通过该认证处理器，可以
	 * 控制 Remember-Me 认证通过时将用户跳转到哪个页面。缺省情况下，目标过滤器
	 * RememberMeAuthenticationFilter 只是放行当前请求。一旦通过该方法设置了
	 * AuthenticationSuccessHandler,该AuthenticationSuccessHandler在认证成功时会被
	 * 调用
	 * Allows control over the destination a remembered user is sent to when they are
	 * successfully authenticated. By default, the filter will just allow the current
	 * request to proceed, but if an {@code AuthenticationSuccessHandler} is set, it will
	 * be invoked and the {@code doFilter()} method will return immediately, thus allowing
	 * the application to redirect the user to a specific URL, regardless of what the
	 * original request was for.
	 *
	 * @param authenticationSuccessHandler the strategy to invoke immediately before
	 *                                     returning from {@code doFilter()}.
	 * @return {@link RememberMeConfigurer} for further customization
	 * @see RememberMeAuthenticationFilter#setAuthenticationSuccessHandler(AuthenticationSuccessHandler)
	 */
	public RememberMeConfigurer<H> authenticationSuccessHandler(
			AuthenticationSuccessHandler authenticationSuccessHandler) {
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		return this;
	}

	/**
	 * 外部可以指定一个要使用的 RememberMeServices，如果不指定，当前配置器对象会自己创建一个
	 * Specify the {@link RememberMeServices} to use.
	 *
	 * @param rememberMeServices the {@link RememberMeServices} to use
	 * @return the {@link RememberMeConfigurer} for further customizations
	 * @see RememberMeServices
	 */
	public RememberMeConfigurer<H> rememberMeServices(
			RememberMeServices rememberMeServices) {
		this.rememberMeServices = rememberMeServices;
		return this;
	}

	/**
	 * Whether the cookie should always be created even if the remember-me parameter is
	 * not set.
	 * <p>
	 * By default this will be set to {@code false}.
	 *
	 * @param alwaysRemember set to {@code true} to always trigger remember me,
	 *                       {@code false} to use the remember-me parameter.
	 * @return the {@link RememberMeConfigurer} for further customization
	 * @see AbstractRememberMeServices#setAlwaysRemember(boolean)
	 */
	public RememberMeConfigurer<H> alwaysRemember(boolean alwaysRemember) {
		this.alwaysRemember = alwaysRemember;
		return this;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void init(H http) throws Exception {
		// 验证是否尚未在同一时间设置
		validateInput();
		// 创建 Remember-Me 机制要使用的 key,
		// 该 key 会被 RememberMeServices ，RememberMeAuthenticationProvider 使用,
		// RememberMeServices 会使用该 key 在 Remember-Me 登录成功创建 RememberMeAuthenticationToken
		// 时传递到 RememberMeAuthenticationToken 对象
		String key = getKey();
		// 准备  RememberMeServices ， 如果外部提供了 RememberMeServices 则使用外部提供值,
		// 如果外部没有提供 RememberMeServices， 则自己创建 RememberMeServices ，
		//  创建逻辑 :
		//  1. 如果外部设定了 tokenRepository, 则创建的是一个 PersistentTokenBasedRememberMeServices 对象;
		//  2. 如果外部没有设定 tokenRepository, 则创建的是一个  TokenBasedRememberMeServices 对象;
		RememberMeServices rememberMeServices = getRememberMeServices(http, key);
		//添加到共享实例中
		http.setSharedObject(RememberMeServices.class, rememberMeServices);
		//
		LogoutConfigurer<H> logoutConfigurer = http.getConfigurer(LogoutConfigurer.class);
		if (logoutConfigurer != null && this.logoutHandler != null) {
			logoutConfigurer.addLogoutHandler(this.logoutHandler);
		}
		// 创建Remember-Me机制要使用的  RememberMeAuthenticationProvider， 注意这里使用了
		// 上面创建的 key，
		RememberMeAuthenticationProvider authenticationProvider = new RememberMeAuthenticationProvider(
				key);
		authenticationProvider = postProcess(authenticationProvider);
		http.authenticationProvider(authenticationProvider);
		// 如果缺省登录页面生成过滤器存在于共享对象池，则告诉它 Remember-Me 参数的名称
		initDefaultLoginFilter(http);
	}

	/**
	 * 配置Http
	 *
	 * @param http
	 */
	@Override
	public void configure(H http) {
		// 创建目标过滤器 RememberMeAuthenticationFilter, 进行属性设置，后置处理，然后配置到安全配置器
		// http 上
		RememberMeAuthenticationFilter rememberMeFilter = new RememberMeAuthenticationFilter(
				http.getSharedObject(AuthenticationManager.class),
				this.rememberMeServices);
		if (this.authenticationSuccessHandler != null) {
			rememberMeFilter
					.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
		}
		rememberMeFilter = postProcess(rememberMeFilter);
		http.addFilter(rememberMeFilter);
	}

	/**
	 * 验证是否尚未在同一时间设置
	 * Validate rememberMeServices and rememberMeCookieName have not been set at
	 * the same time.
	 */
	private void validateInput() {
		if (this.rememberMeServices != null && this.rememberMeCookieName != DEFAULT_REMEMBER_ME_NAME) {
			throw new IllegalArgumentException("Can not set rememberMeCookieName " +
					"and custom rememberMeServices.");
		}
	}

	/**
	 * Returns the HTTP parameter used to indicate to remember the user at time of login.
	 *
	 * @return the HTTP parameter used to indicate to remember the user
	 */
	private String getRememberMeParameter() {
		return this.rememberMeParameter;
	}

	/**
	 * If available, initializes the {@link DefaultLoginPageGeneratingFilter} shared
	 * object.
	 *
	 * @param http the {@link HttpSecurityBuilder} to use
	 */
	private void initDefaultLoginFilter(H http) {
		// 如果缺省登录页面生成过滤器存在于共享对象池，则告诉它 Remember-Me 参数的名称
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null) {
			loginPageGeneratingFilter.setRememberMeParameter(getRememberMeParameter());
		}
	}

	/**
	 * 获取或者创建RememberMeServices实例
	 * Gets the {@link RememberMeServices} or creates the {@link RememberMeServices}.
	 *
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key  the {@link #key(String)}
	 * @return the {@link RememberMeServices} to use
	 * @throws Exception
	 */
	private RememberMeServices getRememberMeServices(H http, String key)
			throws Exception {
		//
		if (this.rememberMeServices != null) {
			// 外部指定了  RememberMeServices 的情形
			if (this.rememberMeServices instanceof LogoutHandler
					&& this.logoutHandler == null) {
				this.logoutHandler = (LogoutHandler) this.rememberMeServices;
			}
			return this.rememberMeServices;
		}
		//创建AbstractRememberMeServices
		// 外部没有指定 RememberMeServices， 则当前配置器自己创建 RememberMeServices 对象
		AbstractRememberMeServices tokenRememberMeServices = createRememberMeServices(
				http, key);
		//设置参数
		tokenRememberMeServices.setParameter(this.rememberMeParameter);
		tokenRememberMeServices.setCookieName(this.rememberMeCookieName);
		if (this.rememberMeCookieDomain != null) {
			tokenRememberMeServices.setCookieDomain(this.rememberMeCookieDomain);
		}
		if (this.tokenValiditySeconds != null) {
			tokenRememberMeServices.setTokenValiditySeconds(this.tokenValiditySeconds);
		}
		if (this.useSecureCookie != null) {
			tokenRememberMeServices.setUseSecureCookie(this.useSecureCookie);
		}
		if (this.alwaysRemember != null) {
			tokenRememberMeServices.setAlwaysRemember(this.alwaysRemember);
		}
		tokenRememberMeServices.afterPropertiesSet();
		this.logoutHandler = tokenRememberMeServices;
		this.rememberMeServices = tokenRememberMeServices;
		return tokenRememberMeServices;
	}

	/**
	 * 如果外部没有提供 RememberMeServices， 通过该方法创建 RememberMeServices ，
	 * 创建逻辑 :
	 * 1. 如果外部设定了 tokenRepository, 则创建的是一个 PersistentTokenBasedRememberMeServices 对象;
	 * 2. 如果外部没有设定 tokenRepository, 则创建的是一个 TokenBasedRememberMeServices 对象;
	 * Creates the {@link RememberMeServices} to use when none is provided. The result is
	 * either {@link PersistentTokenRepository} (if a {@link PersistentTokenRepository} is
	 * specified, else {@link TokenBasedRememberMeServices}.
	 *
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key  the {@link #key(String)}
	 * @return the {@link RememberMeServices} to use
	 */
	private AbstractRememberMeServices createRememberMeServices(H http, String key) {
		return this.tokenRepository == null
				? createTokenBasedRememberMeServices(http, key)
				: createPersistentRememberMeServices(http, key);
	}

	/**
	 * 创建 TokenBasedRememberMeServices 对象，该方法会使用到 UserDetailsService 对象
	 * 和 key (参考方法#getKey)
	 * Creates {@link TokenBasedRememberMeServices}
	 *
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key  the {@link #key(String)}
	 * @return the {@link TokenBasedRememberMeServices}
	 */
	private AbstractRememberMeServices createTokenBasedRememberMeServices(H http,
			String key) {
		//获取UserDetailsService
		UserDetailsService userDetailsService = getUserDetailsService(http);
		//创建
		return new TokenBasedRememberMeServices(key, userDetailsService);
	}

	/**
	 * 创建 PersistentTokenBasedRememberMeServices 对象，该方法会使用到 UserDetailsService 对象
	 * 和 key (参考方法#getKey)
	 * Creates {@link PersistentTokenBasedRememberMeServices}
	 *
	 * @param http the {@link HttpSecurity} to lookup shared objects
	 * @param key  the {@link #key(String)}
	 * @return the {@link PersistentTokenBasedRememberMeServices}
	 */
	private AbstractRememberMeServices createPersistentRememberMeServices(H http,
			String key) {
		UserDetailsService userDetailsService = getUserDetailsService(http);
		return new PersistentTokenBasedRememberMeServices(key, userDetailsService,
				this.tokenRepository);
	}

	/**
	 * 获取最终要使用的 UserDetailsService, 该对象必须通过方法 #userDetailsService(UserDetailsService)
	 * 由外部设定，或者已经存在于 HttpSecurity 安全构建器的共享对象池中。
	 * 如果这两种方式都没有提供 UserDetailsService，则该方法会抛出异常  IllegalStateException
	 * 说找不到 UserDetailsService
	 * Gets the {@link UserDetailsService} to use. Either the explicitly configure
	 * {@link UserDetailsService} from {@link #userDetailsService(UserDetailsService)} or
	 * a shared object from {@link HttpSecurity#getSharedObject(Class)}.
	 *
	 * @param http {@link HttpSecurity} to get the shared {@link UserDetailsService}
	 * @return the {@link UserDetailsService} to use
	 */
	private UserDetailsService getUserDetailsService(H http) {
		if (this.userDetailsService == null) {
			//从共享实例中获取UserDetailsService
			this.userDetailsService = http.getSharedObject(UserDetailsService.class);
		}
		if (this.userDetailsService == null) {
			throw new IllegalStateException("userDetailsService cannot be null. Invoke "
					+ RememberMeConfigurer.class.getSimpleName()
					+ "#userDetailsService(UserDetailsService) or see its javadoc for alternative approaches.");
		}
		return this.userDetailsService;
	}

	/**
	 * 准备一个 key, 用于验证 Remember-Me 认证令牌，
	 * 该 key 使用 UUID 随机字符串
	 * Gets the key to use for validating remember me tokens. If a value was passed into
	 * {@link #key(String)}, then that is returned.
	 * Alternatively, if a key was specified in the
	 * {@link #rememberMeServices(RememberMeServices)}}, then that is returned.
	 * If no key was specified in either of those cases, then a secure random string is
	 * generated.
	 *
	 * @return the remember me key to use
	 */
	private String getKey() {
		if (this.key == null) {
			if (this.rememberMeServices instanceof AbstractRememberMeServices) {
				this.key = ((AbstractRememberMeServices) rememberMeServices).getKey();
			} else {
				this.key = UUID.randomUUID().toString();
			}
		}
		return this.key;
	}
}
