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
package org.springframework.security.web.servletapi;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 框架内部接口，用于创建HttpServletRequest
 * Internal interface for creating a {@link HttpServletRequest}.
 *
 * @author Rob Winch
 * @see HttpServlet3RequestFactory
 * @since 3.2
 */
interface HttpServletRequestFactory {

	/**
	 * Given a {@link HttpServletRequest} returns a {@link HttpServletRequest} that in
	 * most cases wraps the original {@link HttpServletRequest}.
	 *
	 * @param request  the original {@link HttpServletRequest}. Cannot be null.
	 * @param response the original {@link HttpServletResponse}. Cannot be null.
	 * @return a non-null HttpServletRequest
	 */
	HttpServletRequest create(HttpServletRequest request, HttpServletResponse response);
}
