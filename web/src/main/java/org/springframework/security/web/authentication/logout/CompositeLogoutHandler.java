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

package org.springframework.security.web.authentication.logout;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * 登录退出的实现类，里面封装了LogoutHandler
 * Performs a logout through all the {@link LogoutHandler} implementations.
 * If any exception is thrown by
 * {@link #logout(HttpServletRequest, HttpServletResponse, Authentication)},
 * no additional LogoutHandler are invoked.
 *
 * @author Eddú Meléndez
 * @since 4.2.0
 */
public final class CompositeLogoutHandler implements LogoutHandler {

	private final List<LogoutHandler> logoutHandlers;

	public CompositeLogoutHandler(LogoutHandler... logoutHandlers) {
		Assert.notEmpty(logoutHandlers, "LogoutHandlers are required");
		this.logoutHandlers = Arrays.asList(logoutHandlers);
	}

	/**
	 * 添加LogoutHandler
	 * @param logoutHandlers
	 */
	public CompositeLogoutHandler(List<LogoutHandler> logoutHandlers) {
		Assert.notEmpty(logoutHandlers, "LogoutHandlers are required");
		this.logoutHandlers = logoutHandlers;
	}

	/**
	 * 进行登出操作
	 *
	 * @param request        the HTTP request
	 * @param response       the HTTP response
	 * @param authentication the current principal details
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		for (LogoutHandler handler : this.logoutHandlers) {
			handler.logout(request, response, authentication);
		}
	}
}
