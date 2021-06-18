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
package org.springframework.security.web.authentication;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * 用于从{@link HttpServletRequest}转换为特定类型的{@link Authentication}的一种策略。用于通过适当的{@link AuthenticationManager}进行身份验证。
 * 如果结果为空，则表示不应尝试进行身份验证。如果存在无效的身份验证方案值，也可以在{@link#convert（HttpServletRequest）}中抛出{@link AuthenticationException}。
 * A strategy used for converting from a {@link HttpServletRequest} to an
 * {@link Authentication} of particular type. Used to authenticate with
 * appropriate {@link AuthenticationManager}. If the result is null, then it
 * signals that no authentication attempt should be made. It is also possible to
 * throw {@link AuthenticationException} within the
 * {@link #convert(HttpServletRequest)} if there was invalid Authentication
 * scheme value.
 *
 * @author Sergey Bespalov
 * @since 5.2.0
 */
public interface AuthenticationConverter {

	Authentication convert(HttpServletRequest request);

}
