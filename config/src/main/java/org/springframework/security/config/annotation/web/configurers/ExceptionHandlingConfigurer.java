/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.LinkedHashMap;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.RequestMatcherDelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * https://andyboke.blog.csdn.net/article/details/93380379
 * <p>
 * 作为一个配置HttpSecurity的SecurityConfigurer,ExceptionHandlingConfigurer的配置任务如下 :
 * <p>
 * 配置如下安全过滤器Filter
 * ExceptionTranslationFilter
 * ExceptionHandlingConfigurer配置过程中使用到了如下共享对象 :
 * <p>
 * RequestCache
 * 如果该共享对象不存在，则缺省使用一个HttpSessionRequestCache
 * <p>
 * Adds exception handling for Spring Security related exceptions to an application. All
 * properties have reasonable defaults, so no additional configuration is required other
 * than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}.
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link ExceptionTranslationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 * <p>
 * The following shared objects are used:
 *
 * <ul>
 * <li>If no explicit {@link RequestCache}, is provided a {@link RequestCache} shared
 * object is used to replay the request after authentication is successful</li>
 * <li>{@link AuthenticationEntryPoint} - see
 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class ExceptionHandlingConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<ExceptionHandlingConfigurer<H>, H> {

	private AuthenticationEntryPoint authenticationEntryPoint;

	//访问拒绝处理器
	private AccessDeniedHandler accessDeniedHandler;

	private LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> defaultEntryPointMappings = new LinkedHashMap<>();

	private LinkedHashMap<RequestMatcher, AccessDeniedHandler> defaultDeniedHandlerMappings = new LinkedHashMap<>();

	/**
	 * Creates a new instance
	 *
	 * @see HttpSecurity#exceptionHandling()
	 */
	public ExceptionHandlingConfigurer() {
	}

	/**
	 * Shortcut to specify the {@link AccessDeniedHandler} to be used is a specific error
	 * page
	 * 快捷方式，设置访问被拒绝使用的 AccessDeniedHandler 是一个 使用 AccessDeniedHandlerImpl ，
	 * 并且指向设定的错误页面(比如 /errors/401) accessDeniedUrl :
	 * 1. 如果 accessDeniedUrl 为 null，则返回 403 给浏览器端
	 * 2. 如果 accessDeniedUrl 不为 null，是某个 / 开头的有效路径，则 foward 用户到相应的错误页面
	 *
	 * @param accessDeniedUrl the URL to the access denied page (i.e. /errors/401)
	 * @return the {@link ExceptionHandlingConfigurer} for further customization
	 * @see AccessDeniedHandlerImpl
	 * @see #accessDeniedHandler(org.springframework.security.web.access.AccessDeniedHandler)
	 */
	public ExceptionHandlingConfigurer<H> accessDeniedPage(String accessDeniedUrl) {
		//访问拒绝处理器
		AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
		//错误页面url
		accessDeniedHandler.setErrorPage(accessDeniedUrl);
		return accessDeniedHandler(accessDeniedHandler);
	}

	/**
	 * 指定使用的AccessDeniedHandler
	 * Specifies the {@link AccessDeniedHandler} to be used
	 * 设置访问被拒绝时使用的 AccessDeniedHandler
	 *
	 * @param accessDeniedHandler the {@link AccessDeniedHandler} to be used
	 * @return the {@link ExceptionHandlingConfigurer} for further customization
	 */
	public ExceptionHandlingConfigurer<H> accessDeniedHandler(
			AccessDeniedHandler accessDeniedHandler) {
		this.accessDeniedHandler = accessDeniedHandler;
		return this;
	}

	/**
	 * 设置访问拒绝处理器
	 * Sets a default {@link AccessDeniedHandler} to be used which prefers being
	 * invoked for the provided {@link RequestMatcher}. If only a single default
	 * {@link AccessDeniedHandler} is specified, it will be what is used for the
	 * default {@link AccessDeniedHandler}. If multiple default
	 * {@link AccessDeniedHandler} instances are configured, then a
	 * {@link RequestMatcherDelegatingAccessDeniedHandler} will be used.
	 *
	 * @param deniedHandler    the {@link AccessDeniedHandler} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 *                         {@link AccessDeniedHandler}
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 * @since 5.1
	 */
	public ExceptionHandlingConfigurer<H> defaultAccessDeniedHandlerFor(
			AccessDeniedHandler deniedHandler, RequestMatcher preferredMatcher) {
		this.defaultDeniedHandlerMappings.put(preferredMatcher, deniedHandler);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationEntryPoint} to be used.
	 *
	 * <p>
	 * If no {@link #authenticationEntryPoint(AuthenticationEntryPoint)} is specified,
	 * then
	 * {@link #defaultAuthenticationEntryPointFor(AuthenticationEntryPoint, RequestMatcher)}
	 * will be used. The first {@link AuthenticationEntryPoint} will be used as the
	 * default if no matches were found.
	 * </p>
	 *
	 * <p>
	 * If that is not provided defaults to {@link Http403ForbiddenEntryPoint}.
	 * </p>
	 *
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 */
	public ExceptionHandlingConfigurer<H> authenticationEntryPoint(
			AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	/**
	 * Sets a default {@link AuthenticationEntryPoint} to be used which prefers being
	 * invoked for the provided {@link RequestMatcher}. If only a single default
	 * {@link AuthenticationEntryPoint} is specified, it will be what is used for the
	 * default {@link AuthenticationEntryPoint}. If multiple default
	 * {@link AuthenticationEntryPoint} instances are configured, then a
	 * {@link DelegatingAuthenticationEntryPoint} will be used.
	 *
	 * @param entryPoint       the {@link AuthenticationEntryPoint} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 *                         {@link AuthenticationEntryPoint}
	 * @return the {@link ExceptionHandlingConfigurer} for further customizations
	 */
	public ExceptionHandlingConfigurer<H> defaultAuthenticationEntryPointFor(
			AuthenticationEntryPoint entryPoint, RequestMatcher preferredMatcher) {
		this.defaultEntryPointMappings.put(preferredMatcher, entryPoint);
		return this;
	}

	/**
	 * Gets any explicitly configured {@link AuthenticationEntryPoint}
	 *
	 * @return
	 */
	AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.authenticationEntryPoint;
	}

	/**
	 * Gets the {@link AccessDeniedHandler} that is configured.
	 *
	 * @return the {@link AccessDeniedHandler}
	 */
	AccessDeniedHandler getAccessDeniedHandler() {
		return this.accessDeniedHandler;
	}

	// SecurityConfigurer 所定义的配置方法：生成一个 ExceptionTranslationFilter 配置到目标安全构建器
	@Override
	public void configure(H http) {
		// 准备最终要应用到目标 ExceptionTranslationFilter 的 AuthenticationEntryPoint,
		// 先尝试使用外部指定值，未指定的话使用缺省值
		AuthenticationEntryPoint entryPoint = getAuthenticationEntryPoint(http);
		// 创建目标 ExceptionTranslationFilter
		// 这里使用到了 RequestCache， 获取该 RequestCache 对象的过程是 :
		// 先尝试使用 http 中的共享对象，如果没有找到，则使用缺省值， 新建一个 HttpSessionRequestCache 对象
		ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(
				entryPoint, getRequestCache(http));
		// 准备访问被拒绝时要是用的处理器 AccessDeniedHandler
		// 先尝试使用外部指定值，未指定的话使用缺省值
		AccessDeniedHandler deniedHandler = getAccessDeniedHandler(http);
		exceptionTranslationFilter.setAccessDeniedHandler(deniedHandler);
		// 后置处理目标 ExceptionTranslationFilter
		exceptionTranslationFilter = postProcess(exceptionTranslationFilter);
		// 将目标 ExceptionTranslationFilter 添加到目标安全构建器 http
		http.addFilter(exceptionTranslationFilter);
	}

	/**
	 * Gets the {@link AccessDeniedHandler} according to the rules specified by
	 * {@link #accessDeniedHandler(AccessDeniedHandler)}
	 *
	 * @param http the {@link HttpSecurity} used to look up shared
	 *             {@link AccessDeniedHandler}
	 * @return the {@link AccessDeniedHandler} to use
	 */
	AccessDeniedHandler getAccessDeniedHandler(H http) {
		AccessDeniedHandler deniedHandler = this.accessDeniedHandler;
		if (deniedHandler == null) {
			deniedHandler = createDefaultDeniedHandler(http);
		}
		return deniedHandler;
	}

	/**
	 * Gets the {@link AuthenticationEntryPoint} according to the rules specified by
	 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)}
	 *
	 * @param http the {@link HttpSecurity} used to look up shared
	 *             {@link AuthenticationEntryPoint}
	 * @return the {@link AuthenticationEntryPoint} to use
	 */
	AuthenticationEntryPoint getAuthenticationEntryPoint(H http) {
		AuthenticationEntryPoint entryPoint = this.authenticationEntryPoint;
		if (entryPoint == null) {
			entryPoint = createDefaultEntryPoint(http);
		}
		return entryPoint;
	}

	// 创建缺省使用的 AccessDeniedHandler ： 访问被拒绝时的处理器 :
	// 1. 如果 this.defaultDeniedHandlerMappings 为空，则是用一个新的 AccessDeniedHandlerImpl
	// 对象：访问被拒绝时想浏览器返回状态字 403
	// 2. 如果 this.defaultDeniedHandlerMappings 包含一个元素，这是用该元素;
	// 3. 如果 this.defaultDeniedHandlerMappings 包含多个元素，则构造一个
	// RequestMatcherDelegatingAccessDeniedHandler 对象包装和代理
	// this.defaultDeniedHandlerMappings 中的这组元素，此 RequestMatcherDelegatingAccessDeniedHandler
	// 缺省的 AccessDeniedHandler 则是一个新的 AccessDeniedHandlerImpl
	// 对象：访问被拒绝时想浏览器返回状态字 403
	private AccessDeniedHandler createDefaultDeniedHandler(H http) {
		if (this.defaultDeniedHandlerMappings.isEmpty()) {
			return new AccessDeniedHandlerImpl();
		}
		if (this.defaultDeniedHandlerMappings.size() == 1) {
			return this.defaultDeniedHandlerMappings.values().iterator().next();
		}
		return new RequestMatcherDelegatingAccessDeniedHandler(
				this.defaultDeniedHandlerMappings,
				new AccessDeniedHandlerImpl());
	}

	// 创建缺省使用的 AuthenticationEntryPoint ：
	// 1. 如果 this.defaultEntryPointMappings 为空，则使用一个 Http403ForbiddenEntryPoint 实例
	// 2. 如果 this.defaultEntryPointMappings 只包含一个元素，直接使用该元素
	// 3. 如果 this.defaultEntryPointMappings 有多个元素，构建一个 DelegatingAuthenticationEntryPoint
	// 代理对象供使用，该代理对象也是一个 AuthenticationEntryPoint，它将任务代理给
	// this.defaultEntryPointMappings 中的各个 AuthenticationEntryPoint 对象,并将其中第一个设置为
	// 缺省
	private AuthenticationEntryPoint createDefaultEntryPoint(H http) {
		if (this.defaultEntryPointMappings.isEmpty()) {
			return new Http403ForbiddenEntryPoint();
		}
		if (this.defaultEntryPointMappings.size() == 1) {
			return this.defaultEntryPointMappings.values().iterator().next();
		}
		DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(
				this.defaultEntryPointMappings);
		entryPoint.setDefaultEntryPoint(this.defaultEntryPointMappings.values().iterator()
				.next());
		return entryPoint;
	}

	/**
	 * Gets the {@link RequestCache} to use. If one is defined using
	 * {@link #requestCache(org.springframework.security.web.savedrequest.RequestCache)},
	 * then it is used. Otherwise, an attempt to find a {@link RequestCache} shared object
	 * is made. If that fails, an {@link HttpSessionRequestCache} is used
	 *
	 * @param http the {@link HttpSecurity} to attempt to fined the shared object
	 * @return the {@link RequestCache} to use
	 */
	private RequestCache getRequestCache(H http) {
		RequestCache result = http.getSharedObject(RequestCache.class);
		if (result != null) {
			return result;
		}
		return new HttpSessionRequestCache();
	}
}
