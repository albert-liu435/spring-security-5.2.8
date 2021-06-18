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
package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;

/**
 * https://andyboke.blog.csdn.net/article/details/102486132
 * <p>
 * 它可以配置一个默认的URL，用户在成功身份验证时应该发送到该URL。
 * <p>
 * SimpleUrlAuthenticationSuccessHandler – 登录成功时跳转到指定URL
 *
 * <tt>AuthenticationSuccessHandler</tt> which can be configured with a default URL which
 * users should be sent to upon successful authentication.
 * <p>
 * The logic used is that of the {@link AbstractAuthenticationTargetUrlRequestHandler
 * parent class}.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SimpleUrlAuthenticationSuccessHandler extends
		AbstractAuthenticationTargetUrlRequestHandler implements
		AuthenticationSuccessHandler {

	public SimpleUrlAuthenticationSuccessHandler() {
	}

	/**
	 * Constructor which sets the <tt>defaultTargetUrl</tt> property of the base class.
	 *
	 * @param defaultTargetUrl the URL to which the user should be redirected on
	 *                         successful authentication.
	 */
	public SimpleUrlAuthenticationSuccessHandler(String defaultTargetUrl) {
		setDefaultTargetUrl(defaultTargetUrl);
	}

	/**
	 * 验证成功之后执行该方法
	 * Calls the parent class {@code handle()} method to forward or redirect to the target
	 * URL, and then calls {@code clearAuthenticationAttributes()} to remove any leftover
	 * session data.
	 */
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {

		handle(request, response, authentication);
		clearAuthenticationAttributes(request);
	}

	/**
	 * 删除可能在身份验证过程中存储在会话中的与身份验证相关的临时数据。
	 * Removes temporary authentication-related data which may have been stored in the
	 * session during the authentication process.
	 */
	protected final void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		if (session == null) {
			return;
		}

		//清除认证失败信息
		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}
}
