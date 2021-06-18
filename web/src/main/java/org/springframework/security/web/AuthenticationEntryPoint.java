/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.access.ExceptionTranslationFilter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * https://andyboke.blog.csdn.net/article/details/91355520
 * AuthenticationEntryPoint是Spring Security Web一个概念模型接口，顾名思义，他所建模的概念是:“认证入口点”。
 * 它在用户请求处理过程中遇到认证异常时，被ExceptionTranslationFilter用于开启特定认证方案(authentication schema)的认证流程。
 * <p>
 * 该接口只定义了一个方法 :
 * <p>
 * void commence(HttpServletRequest request, HttpServletResponse response,
 * AuthenticationException authException) throws IOException, ServletException;
 * 1
 * 2
 * 这里参数request是遇到了认证异常authException用户请求，response是将要返回给客户的相应，方法commence实现,也就是相应的认证方案逻辑会修改response并返回给用户引导用户进入认证流程。
 * <p>
 * 在该方法被调用前, ExceptionTranslationFilter会做好如下工作 :
 * <p>
 * 填充属性HttpSession,使用属性名称为AbstractAuthenticationProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY
 * <p>
 * 用于启动身份验证方案。 类用来统一处理 AuthenticationException 异常
 * Used by {@link ExceptionTranslationFilter} to commence an authentication scheme.
 *
 * @author Ben Alex
 */
public interface AuthenticationEntryPoint {
	// ~ Methods
	// ========================================================================================================

	/**
	 *
	 * Commences an authentication scheme.
	 * <p>
	 * <code>ExceptionTranslationFilter</code> will populate the <code>HttpSession</code>
	 * attribute named
	 * <code>AbstractAuthenticationProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY</code>
	 * with the requested target URL before calling this method.
	 * <p>
	 * Implementations should modify the headers on the <code>ServletResponse</code> as
	 * necessary to commence the authentication process.
	 *
	 * @param request       that resulted in an <code>AuthenticationException</code>
	 * @param response      so that the user agent can begin authentication
	 * @param authException that caused the invocation
	 */
	void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException;
}
