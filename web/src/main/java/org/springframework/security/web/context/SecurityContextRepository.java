/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;

/**
 *
 *https://blog.csdn.net/fengyilin_henu/article/details/84916822
 * 默认情况下，spring boot用的具体实现类是HttpSessionSecurityContextRepository，把SecurityContext存入到HttpSession的属性中，这个类最主要的配置属性是allowSessionCreation默认是true，
 * 这样当需要为认证用户存储security context而对应的session还不存在时，这个类就会为当前用户创建session对象。
 *
 * 策略接口用于持久化SecurityContext
 * 由{@link SecurityContextPersistenceFilter}使用，以获取应用于当前执行线程的上下文，并在上下文从线程本地存储中删除并且请求完成后存储上下文。
 * 使用的持久性机制将取决于实现，但最常见的是<tt>HttpSession</tt>将用于存储上下文。
 * 存储和加载securityContext都是通过SecurityContextRepository来完成的
 * Strategy used for persisting a {@link SecurityContext} between requests.
 * <p>
 * Used by {@link SecurityContextPersistenceFilter} to obtain the context which should be
 * used for the current thread of execution and to store the context once it has been
 * removed from thread-local storage and the request has completed.
 * <p>
 * The persistence mechanism used will depend on the implementation, but most commonly the
 * <tt>HttpSession</tt> will be used to store the context.
 *
 * @author Luke Taylor
 * @see SecurityContextPersistenceFilter
 * @see HttpSessionSecurityContextRepository
 * @see SaveContextOnUpdateOrErrorResponseWrapper
 * @since 3.0
 */
public interface SecurityContextRepository {

	/**
	 * 获取SecurityContext
	 *
	 * HttpRequestResponseHolder仅仅是一个request和response的封装类，从而允许这个接口的具体实现类对request和response进行包装，返回的对象会传入到后续的filter中。
	 *  从安全上下文存储库(缺省是http session)中读取安全上下文对象
	 * Obtains the security context for the supplied request. For an unauthenticated user,
	 * an empty context implementation should be returned. This method should not return
	 * null.
	 * <p>
	 * The use of the <tt>HttpRequestResponseHolder</tt> parameter allows implementations
	 * to return wrapped versions of the request or response (or both), allowing them to
	 * access implementation-specific state for the request. The values obtained from the
	 * holder will be passed on to the filter chain and also to the <tt>saveContext</tt>
	 * method when it is finally called. Implementations may wish to return a subclass of
	 * {@link SaveContextOnUpdateOrErrorResponseWrapper} as the response object, which
	 * guarantees that the context is persisted when an error or redirect occurs.
	 *
	 * @param requestResponseHolder holder for the current request and response for which
	 *                              the context should be loaded.
	 * @return The security context which should be used for the current request, never
	 * null.
	 */
	SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

	/**
	 * 存储security context
	 * Stores the security context on completion of a request.
	 *
	 * @param context  the non-null context which was obtained from the holder.
	 * @param request
	 * @param response
	 */
	void saveContext(SecurityContext context, HttpServletRequest request,
			HttpServletResponse response);

	/**
	 * 允许查询存储库是否包含当前请求的安全上下文。
	 * Allows the repository to be queried as to whether it contains a security context
	 * for the current request.
	 *
	 * @param request the current request
	 * @return true if a context is found for the request, false otherwise
	 */
	boolean containsContext(HttpServletRequest request);
}
