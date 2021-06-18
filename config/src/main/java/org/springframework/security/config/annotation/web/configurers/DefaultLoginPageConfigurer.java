/*
 * Copyright 2002-2013 the original author or authors.
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

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfToken;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

/**
 * https://andyboke.blog.csdn.net/article/details/91346516
 * 作为一个配置HttpSecurity的SecurityConfigurer,DefaultLoginPageConfigurer的配置任务如下 :
 * <p>
 * 配置如下安全过滤器Filter
 * <p>
 * DefaultLoginPageGeneratingFilter
 * 仅在没有通过FormLoginConfigurer指定一个登录页面时应用
 * <p>
 * 创建如下共享对象
 * <p>
 * DefaultLoginPageGeneratingFilter
 * DefaultLoginPageConfigurer在配置过程中还使用到了如下配置器 :
 * * ExceptionHandlingConfigurer
 * > 用于判断是否应该配置添加DefaultLoginPageGeneratingFilter
 * <p>
 * 另外:
 * <p>
 * FormLoginConfigurer如果也被使用，它会有一个初始化动作专门设置DefaultLoginPageConfigurer对象属性formLoginEnabled为true。
 * <p>
 * LogoutConfigurer如果也被使用，LogoutConfigurer初始化时会设置DefaultLoginPageConfigurer的属性logoutSuccessUrl
 * <p>
 * 添加默认生成登录页面的过滤器
 * Adds a Filter that will generate a login page if one is not specified otherwise when
 * using {@link WebSecurityConfigurerAdapter}.
 *
 * <p>
 * By default an
 * {@link org.springframework.security.web.access.channel.InsecureChannelProcessor} and a
 * {@link org.springframework.security.web.access.channel.SecureChannelProcessor} will be
 * registered.
 * </p>
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following Filters are conditionally populated
 *
 * <ul>
 * <li>{@link DefaultLoginPageGeneratingFilter} if the {@link FormLoginConfigurer} did not
 * have a login page specified</li>
 * </ul>
 * <p>
 * 已创建共享对象
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * No shared objects are created. isLogoutRequest <h2>Shared Objects Used</h2>
 * <p>
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link org.springframework.security.web.PortMapper} is used to create the default
 * {@link org.springframework.security.web.access.channel.ChannelProcessor} instances</li>
 * <li>{@link FormLoginConfigurer} is used to determine if the
 * {@link DefaultLoginPageConfigurer} should be added and how to configure it.</li>
 * </ul>
 *
 * @author Rob Winch
 * @see WebSecurityConfigurerAdapter
 * @since 3.2
 */
public final class DefaultLoginPageConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<DefaultLoginPageConfigurer<H>, H> {
	// 安全过滤器，用于生成缺省的登录页面
	private DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = new DefaultLoginPageGeneratingFilter();
	// 安全过滤器，用于生成缺省的退出页面
	private DefaultLogoutPageGeneratingFilter logoutPageGeneratingFilter = new DefaultLogoutPageGeneratingFilter();

	//初始化操作
	@Override
	public void init(H http) {
		// 对  loginPageGeneratingFilter, logoutPageGeneratingFilter 进行属性设置
		// 箭头函数，用于从请求中检测  CsrfToken
		Function<HttpServletRequest, Map<String, String>> hiddenInputs = request -> {
			CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			if (token == null) {
				return Collections.emptyMap();
			}
			return Collections.singletonMap(token.getParameterName(), token.getToken());
		};
		this.loginPageGeneratingFilter.setResolveHiddenInputs(hiddenInputs);
		this.logoutPageGeneratingFilter.setResolveHiddenInputs(hiddenInputs);
		//设置共享实例
		//  设置共享对象 DefaultLoginPageGeneratingFilter
		http.setSharedObject(DefaultLoginPageGeneratingFilter.class,
				loginPageGeneratingFilter);
	}

	// 配置器配置方法
	@Override
	@SuppressWarnings("unchecked")
	public void configure(H http) {
		// 从  ExceptionHandlingConfigurer 中检测 AuthenticationEntryPoint 是否设置
		AuthenticationEntryPoint authenticationEntryPoint = null;
		ExceptionHandlingConfigurer<?> exceptionConf = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionConf != null) {
			authenticationEntryPoint = exceptionConf.getAuthenticationEntryPoint();
		}
// 如果  loginPageGeneratingFilter 被启用 并且  authenticationEntryPoint 未被设置，
		// 则将 loginPageGeneratingFilter,logoutPageGeneratingFilter 双双添加到
		// HttpSecurity http
		// loginPageGeneratingFilter 是否被启用的判断是有其他配置器设置的，可以
		// 参考 DefaultLoginPageGeneratingFilter 源代码，具体来讲，如果
		// 启用了 表单登录认证， OpenID登录认证 或者 OAuth2 登录认证，
		// 则认为 DefaultLoginPageGeneratingFilter 被启用
		if (loginPageGeneratingFilter.isEnabled() && authenticationEntryPoint == null) {
			loginPageGeneratingFilter = postProcess(loginPageGeneratingFilter);
			http.addFilter(loginPageGeneratingFilter);
			http.addFilter(this.logoutPageGeneratingFilter);
		}
	}

}
