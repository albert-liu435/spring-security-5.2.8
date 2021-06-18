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
package org.springframework.security.web.authentication.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * 当身份验证发生时，允许对HttpSession相关行为的可插拔支持。
 * Allows pluggable support for HttpSession-related behaviour when an authentication
 * occurs.
 * <p>
 * 典型的用法是确保会话存在或更改会话Id以防止会话固定攻击。
 * Typical use would be to make sure a session exists or to change the session Id to guard
 * against session-fixation attacks.
 *
 * @author Luke Taylor
 * @since
 */
public interface SessionAuthenticationStrategy {

	/**
	 * 在发生新身份验证时执行Http会话相关功能。
	 * Performs Http session-related functionality when a new authentication occurs.
	 *
	 * @throws SessionAuthenticationException if it is decided that the authentication is
	 *                                        not allowed for the session. This will typically be because the user has too many
	 *                                        sessions open at once.
	 */
	void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) throws SessionAuthenticationException;

}
