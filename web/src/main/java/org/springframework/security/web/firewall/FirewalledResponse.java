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
package org.springframework.security.web.firewall;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/**
 * https://andyboke.blog.csdn.net/article/details/90573479
 * FirewalledResponse是Spring Security Web提供的一个HttpServletResponse实现，是一个带有防火墙增强安全能力的HttpServletResponse实现，被HttpFirewall对象用于对一个HttpServletResponse进行安全增强的包装器。
 * <p>
 * 通过FirewalledResponse的包装，它对HttpServletResponse做了如下安全增强:
 * <p>
 * 设置或者添加响应头部时，确保写入的头部值不包含\r或者\n;
 * 有关方法 : #setHeader,#addHeader
 * <p>
 * 添加cookie时，确保写入的值不包含\r或者\n;
 * 有关方法 : #addCookie
 * <p>
 * 重定向时，确保重定向location中不包含\r或者\n;
 * 有关方法 : #sendRedirect
 * <p>
 * FirewalledResponse对写入响应的值所做的增强逻辑中，如果所写入的值违反了规则，则会抛出异常IllegalArgumentException。
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @author Gabriel Lavoie
 * @author Luke Butters
 */
class FirewalledResponse extends HttpServletResponseWrapper {
	private static final String LOCATION_HEADER = "Location";
	private static final String SET_COOKIE_HEADER = "Set-Cookie";

	FirewalledResponse(HttpServletResponse response) {
		super(response);
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		// TODO: implement pluggable validation, instead of simple blacklisting.
		// SEC-1790. Prevent redirects containing CRLF
		validateCrlf(LOCATION_HEADER, location);
		super.sendRedirect(location);
	}

	@Override
	public void setHeader(String name, String value) {
		validateCrlf(name, value);
		super.setHeader(name, value);
	}

	@Override
	public void addHeader(String name, String value) {
		validateCrlf(name, value);
		super.addHeader(name, value);
	}

	@Override
	public void addCookie(Cookie cookie) {
		if (cookie != null) {
			validateCrlf(SET_COOKIE_HEADER, cookie.getName());
			validateCrlf(SET_COOKIE_HEADER, cookie.getValue());
			validateCrlf(SET_COOKIE_HEADER, cookie.getPath());
			validateCrlf(SET_COOKIE_HEADER, cookie.getDomain());
			validateCrlf(SET_COOKIE_HEADER, cookie.getComment());
		}
		super.addCookie(cookie);
	}

	void validateCrlf(String name, String value) {
		if (hasCrlf(name) || hasCrlf(value)) {
			throw new IllegalArgumentException(
					"Invalid characters (CR/LF) in header " + name);
		}
	}

	private boolean hasCrlf(String value) {
		return value != null && (value.indexOf('\n') != -1 || value.indexOf('\r') != -1);
	}
}
