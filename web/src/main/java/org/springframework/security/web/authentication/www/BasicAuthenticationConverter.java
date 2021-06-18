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
package org.springframework.security.web.authentication.www;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * 用于从HttpServletRequest转换为UsernamePasswordAuthenticationToken用于验证
 * Converts from a HttpServletRequest to
 * {@link UsernamePasswordAuthenticationToken} that can be authenticated. Null
 * authentication possible if there was no Authorization header with Basic
 * authentication scheme.
 *
 * @author Sergey Bespalov
 * @since 5.2.0
 */
public class BasicAuthenticationConverter implements AuthenticationConverter {

	public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	//编码格式
	private Charset credentialsCharset = StandardCharsets.UTF_8;

	public BasicAuthenticationConverter() {
		this(new WebAuthenticationDetailsSource());
	}

	public BasicAuthenticationConverter(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public Charset getCredentialsCharset() {
		return this.credentialsCharset;
	}

	public void setCredentialsCharset(Charset credentialsCharset) {
		this.credentialsCharset = credentialsCharset;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return this.authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * 用于从{@link HttpServletRequest}转换为特定类型的{@link Authentication}的一种策略。用于通过适当的{@link AuthenticationManager}进行身份验证。
	 * * 如果结果为空，则表示不应尝试进行身份验证。如果存在无效的身份验证方案值，也可以在{@link#convert（HttpServletRequest）}中抛出{@link AuthenticationException}。
	 *
	 * @param request
	 * @return
	 */
	@Override
	public UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {
		//获取header中的信息，即获取HttpBasic的认证信息
		String header = request.getHeader(AUTHORIZATION);
		if (header == null) {
			return null;
		}

		header = header.trim();
		//如果不是以Basic开头则返回位null
		if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
			return null;
		}
		//
		if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
			throw new BadCredentialsException("Empty basic authentication token");
		}
		//采用的是Base64进行解码
		byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(base64Token);
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException(
					"Failed to decode basic authentication token");
		}
		//采用Base64解码
		String token = new String(decoded, getCredentialsCharset(request));
		//
		int delim = token.indexOf(":");

		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}
		//获取用户名和密码封装到UsernamePasswordAuthenticationToken
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(token.substring(0, delim), token.substring(delim + 1));
		result.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return result;
	}

	protected Charset getCredentialsCharset(HttpServletRequest request) {
		return getCredentialsCharset();
	}

}
