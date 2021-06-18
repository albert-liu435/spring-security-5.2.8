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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.DelegatingLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * https://felord.cn/spring-security-logout.html
 * https://andyboke.blog.csdn.net/article/details/91346994
 * <p>
 * 作为一个配置HttpSecurity的SecurityConfigurer,LogoutConfigurer的配置任务如下 :
 * <p>
 * 配置如下安全过滤器Filter
 * <p>
 * LogoutFilter
 * 会根据所设置的logoutUrl,logoutRequestMatcher,以及配置器CsrfConfigurer中是否启用csrf保护等信息构建最终所使用的退出LogoutRequestMatcher,也就是触发退出的url匹配器。
 * 会根据所设置的属性logoutSuccessHandler,defaultLogoutSuccessHandlerMappings,logoutSuccessUrl确定最终要使用LogoutSuccessHandler，它们三个之间的应用优先级是 : logoutSuccessHandler > defaultLogoutSuccessHandlerMappings > logoutSuccessUrl。
 * LogoutConfigurer所被设置的所有LogoutHandler都会被应用，最后一个LogoutHandler总是LogoutConfigurer自己提供的一个SecurityContextLogoutHandler,该SecurityContextLogoutHandler也可以被调用者设置。
 * <p>
 * <p>
 * LogoutConfigurer 提供了 logoutRequestMatcher(RequestMatcher logoutRequestMatcher)、logoutUrl(Sring logoutUrl) 两种方式来定义退出登录请求的 URL 。它们作用是相同的，你选择其中一种方式即可。
 * <p>
 * Adds logout support. Other {@link SecurityConfigurer} instances may invoke
 * {@link #addLogoutHandler(LogoutHandler)} in the {@link #init(HttpSecurityBuilder)} phase.
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following Filters are populated
 *
 * <ul>
 * <li>
 * {@link LogoutFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * No shared Objects are created
 *
 * <h2>Shared Objects Used</h2>
 * <p>
 * No shared objects are used.
 *
 * @author Rob Winch
 * @author Onur Kagan Ozcan
 * @see RememberMeConfigurer
 * @since 3.2
 */
public final class LogoutConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<LogoutConfigurer<H>, H> {
	// 退出时要执行的处理器，可以有多个, contextLogoutHandler 总是最后一个
	private List<LogoutHandler> logoutHandlers = new ArrayList<>();
	private SecurityContextLogoutHandler contextLogoutHandler = new SecurityContextLogoutHandler();
	// 退出成功时跳转的页面，缺省使用 /login?logout
	private String logoutSuccessUrl = "/login?logout";
	//退出成功后执行的逻辑的抽象根本接口。
	// 退出成功时的处理器，如果该属性被设置，logoutSuccessUrl 的值会被忽略
	private LogoutSuccessHandler logoutSuccessHandler;
	// 触发退出登录的url，缺省使用 /logout
	// 如果是使用了 csrf 保护，访问该地址必须使用 POST, 如果没有使用 csrf 保护， 也可以使用 GET,
	// PUT,DELETE
	// logoutUrl 和 logoutRequestMatcher 通常二选其一使用，最佳实践建议使用 logoutUrl
	private String logoutUrl = "/logout";
	// 触发退出登录的 RequestMatcher, 缺省为 null
	// logoutUrl 和 logoutRequestMatcher 通常二选其一使用，最佳实践建议使用 logoutUrl
	private RequestMatcher logoutRequestMatcher;
	private boolean permitAll;
	// 如果 logoutSuccessHandler 被设置，或者 logoutSuccessUrl 被设置为非缺省值,
	// customLogoutSuccess 为 true
	private boolean customLogoutSuccess;

	private LinkedHashMap<RequestMatcher, LogoutSuccessHandler> defaultLogoutSuccessHandlerMappings =
			new LinkedHashMap<>();

	/**
	 * 创建一个实例
	 * Creates a new instance
	 *
	 * @see HttpSecurity#logout()
	 */
	public LogoutConfigurer() {
	}

	/**
	 * 添加Logout处理器
	 * Adds a {@link LogoutHandler}.
	 * {@link SecurityContextLogoutHandler} and {@link LogoutSuccessEventPublishingLogoutHandler} are added as
	 * last {@link LogoutHandler} instances by default.
	 *
	 * @param logoutHandler the {@link LogoutHandler} to add
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> addLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandlers.add(logoutHandler);
		return this;
	}

	/**
	 * 是否在退出时清除当前用户的认证信息
	 * Specifies if {@link SecurityContextLogoutHandler} should clear the {@link Authentication} at the time of logout.
	 *
	 * @param clearAuthentication true {@link SecurityContextLogoutHandler} should clear the {@link Authentication} (default), or false otherwise.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> clearAuthentication(boolean clearAuthentication) {
		contextLogoutHandler.setClearAuthentication(clearAuthentication);
		return this;
	}


	/**
	 * 是否移除 HttpSession
	 * Configures {@link SecurityContextLogoutHandler} to invalidate the
	 * {@link HttpSession} at the time of logout.
	 *
	 * @param invalidateHttpSession true if the {@link HttpSession} should be invalidated
	 *                              (default), or false otherwise.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> invalidateHttpSession(boolean invalidateHttpSession) {
		contextLogoutHandler.setInvalidateHttpSession(invalidateHttpSession);
		return this;
	}

	/**
	 * 设置logout后的url
	 * The URL that triggers log out to occur (default is "/logout"). If CSRF protection
	 * is enabled (default), then the request must also be a POST. This means that by
	 * default POST "/logout" is required to trigger a log out. If CSRF protection is
	 * disabled, then any HTTP method is allowed.
	 *
	 * <p>
	 * It is considered best practice to use an HTTP POST on any action that changes state
	 * (i.e. log out) to protect against <a
	 * href="https://en.wikipedia.org/wiki/Cross-site_request_forgery">CSRF attacks</a>. If
	 * you really want to use an HTTP GET, you can use
	 * <code>logoutRequestMatcher(new AntPathRequestMatcher(logoutUrl, "GET"));</code>
	 * </p>
	 *
	 * @param logoutUrl the URL that will invoke logout.
	 * @return the {@link LogoutConfigurer} for further customization
	 * @see #logoutRequestMatcher(RequestMatcher)
	 * @see HttpSecurity#csrf()
	 */
	public LogoutConfigurer<H> logoutUrl(String logoutUrl) {
		// 使用 logoutUrl 的时候将 logoutRequestMatcher 设置为 null
		this.logoutRequestMatcher = null;
		this.logoutUrl = logoutUrl;
		return this;
	}

	/**
	 * logout的请求匹配器
	 * The RequestMatcher that triggers log out to occur. In most circumstances users will
	 * use {@link #logoutUrl(String)} which helps enforce good practices.
	 *
	 * @param logoutRequestMatcher the RequestMatcher used to determine if logout should
	 *                             occur.
	 * @return the {@link LogoutConfigurer} for further customization
	 * @see #logoutUrl(String)
	 */
	public LogoutConfigurer<H> logoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		this.logoutRequestMatcher = logoutRequestMatcher;
		return this;
	}

	/**
	 * 登出成功后会被重定向到此 URL ，你可以写一个Controller 来完成最终返回，但是需要支持 GET 请求和 匿名访问 。 通过 setDefaultTargetUrl 方法注入到 LogoutSuccessHandler
	 * The URL to redirect to after logout has occurred. The default is "/login?logout".
	 * This is a shortcut for invoking {@link #logoutSuccessHandler(LogoutSuccessHandler)}
	 * with a {@link SimpleUrlLogoutSuccessHandler}.
	 *
	 * @param logoutSuccessUrl the URL to redirect to after logout occurred
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> logoutSuccessUrl(String logoutSuccessUrl) {
		this.customLogoutSuccess = true;
		this.logoutSuccessUrl = logoutSuccessUrl;
		return this;
	}

	/**
	 * A shortcut for {@link #permitAll(boolean)} with <code>true</code> as an argument.
	 *
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> permitAll() {
		return permitAll(true);
	}

	/**
	 * 删除指定的 cookies
	 * Allows specifying the names of cookies to be removed on logout success. This is a
	 * shortcut to easily invoke {@link #addLogoutHandler(LogoutHandler)} with a
	 * {@link CookieClearingLogoutHandler}.
	 *
	 * @param cookieNamesToClear the names of cookies to be removed on logout success.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> deleteCookies(String... cookieNamesToClear) {
		// 设置退出成功时要删除的cookie的名称
		// 其实是添加了一个退出处理器 CookieClearingLogoutHandler
		return addLogoutHandler(new CookieClearingLogoutHandler(cookieNamesToClear));
	}

	/**
	 * 设置logout的请求成功处理器
	 * Sets the {@link LogoutSuccessHandler} to use. If this is specified,
	 * {@link #logoutSuccessUrl(String)} is ignored.
	 *
	 * @param logoutSuccessHandler the {@link LogoutSuccessHandler} to use after a user
	 *                             has been logged out.
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> logoutSuccessHandler(
			LogoutSuccessHandler logoutSuccessHandler) {
		this.logoutSuccessUrl = null;// 设置 logoutSuccessUrl 为 null
		this.customLogoutSuccess = true;
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	/**
	 * 用来构造默认的 LogoutSuccessHandler 我们可以通过添加多个来实现从不同 URL 退出执行不同的逻辑。
	 * Sets a default {@link LogoutSuccessHandler} to be used which prefers being invoked
	 * for the provided {@link RequestMatcher}. If no {@link LogoutSuccessHandler} is
	 * specified a {@link SimpleUrlLogoutSuccessHandler} will be used.
	 * If any default {@link LogoutSuccessHandler} instances are configured, then a
	 * {@link DelegatingLogoutSuccessHandler} will be used that defaults to a
	 * {@link SimpleUrlLogoutSuccessHandler}.
	 *
	 * @param handler          the {@link LogoutSuccessHandler} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 *                         {@link LogoutSuccessHandler}
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> defaultLogoutSuccessHandlerFor(
			LogoutSuccessHandler handler, RequestMatcher preferredMatcher) {
		Assert.notNull(handler, "handler cannot be null");
		Assert.notNull(preferredMatcher, "preferredMatcher cannot be null");
		this.defaultLogoutSuccessHandlerMappings.put(preferredMatcher, handler);
		return this;
	}

	/**
	 * Grants access to the {@link #logoutSuccessUrl(String)} and the
	 * {@link #logoutUrl(String)} for every user.
	 *
	 * @param permitAll if true grants access, else nothing is done
	 * @return the {@link LogoutConfigurer} for further customization.
	 */
	public LogoutConfigurer<H> permitAll(boolean permitAll) {
		this.permitAll = permitAll;
		return this;
	}

	/**
	 * 如果设置了 logoutSuccessHandler，则使用 logoutSuccessHandler， 否则
	 * 基于 logoutSuccessUrl 和 defaultLogoutSuccessHandlerMappings 创建缺省的 LogoutSuccessHandler
	 * 并最终使用
	 * Gets the {@link LogoutSuccessHandler} if not null, otherwise creates a new
	 * {@link SimpleUrlLogoutSuccessHandler} using the {@link #logoutSuccessUrl(String)}.
	 *
	 * @return the {@link LogoutSuccessHandler} to use
	 */
	private LogoutSuccessHandler getLogoutSuccessHandler() {
		LogoutSuccessHandler handler = this.logoutSuccessHandler;
		if (handler == null) {
			handler = createDefaultSuccessHandler();
		}
		return handler;
	}

	// 基于 logoutSuccessUrl 和 defaultLogoutSuccessHandlerMappings 创建缺省的 LogoutSuccessHandler
	// 1. 如果 defaultLogoutSuccessHandlerMappings 不为空，则使用基于它的 DelegatingLogoutSuccessHandler
	// 2. 如果 defaultLogoutSuccessHandlerMappings 为空，使用基于 logoutSuccessUrl 创建的
	//    SimpleUrlLogoutSuccessHandler
	private LogoutSuccessHandler createDefaultSuccessHandler() {
		SimpleUrlLogoutSuccessHandler urlLogoutHandler = new SimpleUrlLogoutSuccessHandler();
		urlLogoutHandler.setDefaultTargetUrl(logoutSuccessUrl);
		if (defaultLogoutSuccessHandlerMappings.isEmpty()) {
			return urlLogoutHandler;
		}
		DelegatingLogoutSuccessHandler successHandler = new DelegatingLogoutSuccessHandler(defaultLogoutSuccessHandlerMappings);
		successHandler.setDefaultLogoutSuccessHandler(urlLogoutHandler);
		return successHandler;
	}

	@Override
	public void init(H http) {
		// 根据 permitAll 属性，对 HttpSecurity 构建器 http 进行设置如下 url 放行设置 :
		// 1. this.logoutSuccessUrl : 退出成功时所跳转的 url
		// 2. this.getLogoutRequestMatcher(http) 所匹配的 url : 触发退出的url
		if (permitAll) {
			PermitAllSupport.permitAll(http, this.logoutSuccessUrl);
			PermitAllSupport.permitAll(http, this.getLogoutRequestMatcher(http));
		}
		// 对  DefaultLoginPageGeneratingFilter 进行补充设置
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null && !isCustomLogoutSuccess()) {
			// 如果 DefaultLoginPageGeneratingFilter 存在于共享对象，并且
			// 退出成功url没有使用缺省值的情况下，对 DefaultLoginPageGeneratingFilter
			// 进行设置属性 logoutSuccessUrl
			loginPageGeneratingFilter.setLogoutSuccessUrl(getLogoutSuccessUrl());
		}
	}

	@Override
	public void configure(H http) throws Exception {
		// 创建 LogoutFilter 过滤器添加到 HttpSecurity http
		LogoutFilter logoutFilter = createLogoutFilter(http);
		http.addFilter(logoutFilter);
	}

	/**
	 * Returns true if the logout success has been customized via
	 * {@link #logoutSuccessUrl(String)} or
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)}.
	 *
	 * @return true if logout success handling has been customized, else false
	 */
	boolean isCustomLogoutSuccess() {
		return customLogoutSuccess;
	}

	/**
	 * Gets the logoutSuccesUrl or null if a
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)} was configured.
	 *
	 * @return the logoutSuccessUrl
	 */
	private String getLogoutSuccessUrl() {
		return logoutSuccessUrl;
	}

	/**
	 * Gets the {@link LogoutHandler} instances that will be used.
	 *
	 * @return the {@link LogoutHandler} instances. Cannot be null.
	 */
	List<LogoutHandler> getLogoutHandlers() {
		return logoutHandlers;
	}

	/**
	 * Creates the {@link LogoutFilter} using the {@link LogoutHandler} instances, the
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)} and the
	 * {@link #logoutUrl(String)}.
	 *
	 * @param http the builder to use
	 * @return the {@link LogoutFilter} to use.
	 */
	private LogoutFilter createLogoutFilter(H http) {
		// 这里确保 contextLogoutHandler 总是所有 logoutHandlers 中的最后一个
		logoutHandlers.add(contextLogoutHandler);
		logoutHandlers.add(postProcess(new LogoutSuccessEventPublishingLogoutHandler()));
		LogoutHandler[] handlers = logoutHandlers
				.toArray(new LogoutHandler[0]);
		// 构造  LogoutFilter 并返回
		LogoutFilter result = new LogoutFilter(getLogoutSuccessHandler(), handlers);
		// 根据属性  logoutRequestMatcher， url 设置， csrf 保护设置构建最终使用的
		// logoutRequestMatcher 并设置到 LogoutFilter 上
		result.setLogoutRequestMatcher(getLogoutRequestMatcher(http));
		result = postProcess(result);
		return result;
	}

	// 根据设置构建最终使用的 logoutRequestMatcher:
	// 1. 如果设置了属性 logoutRequestMatcher , 则使用属性 logoutRequestMatcher,否则
	// 2. 如果启用了 csrf 保护，使用 logoutUrl, POST 构建一个 AntPathRequestMatcher
	//    到 logoutRequestMatcher 属性并最终使用,
	// 3. 如果没有启用 csrf 保护，使用 logoutUrl,GET/POST/PUT/DELETE 构造一个
	//   OrRequestMatcher 到 logoutRequestMatcher 属性并最终使用,
	@SuppressWarnings("unchecked")
	private RequestMatcher getLogoutRequestMatcher(H http) {
		if (logoutRequestMatcher != null) {
			return logoutRequestMatcher;
		}
		if (http.getConfigurer(CsrfConfigurer.class) != null) {
			this.logoutRequestMatcher = new AntPathRequestMatcher(this.logoutUrl, "POST");
		} else {
			this.logoutRequestMatcher = new OrRequestMatcher(
					new AntPathRequestMatcher(this.logoutUrl, "GET"),
					new AntPathRequestMatcher(this.logoutUrl, "POST"),
					new AntPathRequestMatcher(this.logoutUrl, "PUT"),
					new AntPathRequestMatcher(this.logoutUrl, "DELETE")
			);
		}
		return this.logoutRequestMatcher;
	}
}
