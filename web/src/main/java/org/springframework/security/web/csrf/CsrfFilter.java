/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.csrf;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import static java.lang.Boolean.TRUE;

/**
 * 防止伪造请求攻击
 * 在 spring4 这个版本中被默认开启的一个过滤器，用于防止 csrf 攻击，了解前后端分离的人一定不会对这个攻击方式感到陌生，前后端使用 json 交互需要注意的一个问题。
 * <p>
 * Applies
 * <a href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)" >CSRF</a>
 * protection using a synchronizer token pattern. Developers are required to ensure that
 * {@link CsrfFilter} is invoked for any request that allows state to change. Typically
 * this just means that they should ensure their web application follows proper REST
 * semantics (i.e. do not change state with the HTTP methods GET, HEAD, TRACE, OPTIONS).
 * </p>
 *
 * <p>
 * Typically the {@link CsrfTokenRepository} implementation chooses to store the
 * {@link CsrfToken} in {@link HttpSession} with {@link HttpSessionCsrfTokenRepository}
 * wrapped by a {@link LazyCsrfTokenRepository}. This is preferred to storing the token in
 * a cookie which can be modified by a client application.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CsrfFilter extends OncePerRequestFilter {
	/**
	 * 默认的Csrf的请求匹配器
	 * The default {@link RequestMatcher} that indicates if CSRF protection is required or
	 * not. The default is to ignore GET, HEAD, TRACE, OPTIONS and process all other
	 * requests.
	 */
	public static final RequestMatcher DEFAULT_CSRF_MATCHER = new DefaultRequiresCsrfMatcher();

	/**
	 * 将给定请求标记为不应筛选的请求时使用的属性名称。
	 * The attribute name to use when marking a given request as one that should not be filtered.
	 * <p>
	 * To use, set the attribute on your {@link HttpServletRequest}:
	 * <pre>
	 * 	CsrfFilter.skipRequest(request);
	 * </pre>
	 */
	private static final String SHOULD_NOT_FILTER = "SHOULD_NOT_FILTER" + CsrfFilter.class.getName();

	private final Log logger = LogFactory.getLog(getClass());

	private final CsrfTokenRepository tokenRepository;
	//请求匹配器
	private RequestMatcher requireCsrfProtectionMatcher = DEFAULT_CSRF_MATCHER;
	//用于处理AccessDeniedException异常的处理器
	private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

	public CsrfFilter(CsrfTokenRepository csrfTokenRepository) {
		Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
		this.tokenRepository = csrfTokenRepository;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return TRUE.equals(request.getAttribute(SHOULD_NOT_FILTER));
	}

	/*
	过滤器
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.web.filter.OncePerRequestFilter#doFilterInternal(javax.servlet
	 * .http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * javax.servlet.FilterChain)
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		request.setAttribute(HttpServletResponse.class.getName(), response);
		//获取CsrfToken
		CsrfToken csrfToken = this.tokenRepository.loadToken(request);
		//判断是否为true
		final boolean missingToken = csrfToken == null;
		if (missingToken) {
			csrfToken = this.tokenRepository.generateToken(request);
			this.tokenRepository.saveToken(csrfToken, request, response);
		}
		request.setAttribute(CsrfToken.class.getName(), csrfToken);
		request.setAttribute(csrfToken.getParameterName(), csrfToken);

		if (!this.requireCsrfProtectionMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		String actualToken = request.getHeader(csrfToken.getHeaderName());
		if (actualToken == null) {
			actualToken = request.getParameter(csrfToken.getParameterName());
		}
		if (!csrfToken.getToken().equals(actualToken)) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Invalid CSRF token found for "
						+ UrlUtils.buildFullRequestUrl(request));
			}
			if (missingToken) {
				this.accessDeniedHandler.handle(request, response,
						new MissingCsrfTokenException(actualToken));
			} else {
				this.accessDeniedHandler.handle(request, response,
						new InvalidCsrfTokenException(csrfToken, actualToken));
			}
			return;
		}

		filterChain.doFilter(request, response);
	}

	public static void skipRequest(HttpServletRequest request) {
		request.setAttribute(SHOULD_NOT_FILTER, TRUE);
	}

	/**
	 * Specifies a {@link RequestMatcher} that is used to determine if CSRF protection
	 * should be applied. If the {@link RequestMatcher} returns true for a given request,
	 * then CSRF protection is applied.
	 *
	 * <p>
	 * The default is to apply CSRF protection for any HTTP method other than GET, HEAD,
	 * TRACE, OPTIONS.
	 * </p>
	 *
	 * @param requireCsrfProtectionMatcher the {@link RequestMatcher} used to determine if
	 *                                     CSRF protection should be applied.
	 */
	public void setRequireCsrfProtectionMatcher(
			RequestMatcher requireCsrfProtectionMatcher) {
		Assert.notNull(requireCsrfProtectionMatcher,
				"requireCsrfProtectionMatcher cannot be null");
		this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
	}

	/**
	 * Specifies a {@link AccessDeniedHandler} that should be used when CSRF protection
	 * fails.
	 *
	 * <p>
	 * The default is to use AccessDeniedHandlerImpl with no arguments.
	 * </p>
	 *
	 * @param accessDeniedHandler the {@link AccessDeniedHandler} to use
	 */
	public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
		this.accessDeniedHandler = accessDeniedHandler;
	}

	/**
	 * 默认的伪造请求匹配器
	 */
	private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {
		//允许的请求的方法
		private final HashSet<String> allowedMethods = new HashSet<>(
				Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));

		/*决定策略实现的规则是否与提供的请求匹配
		 * (non-Javadoc)
		 *
		 * @see
		 * org.springframework.security.web.util.matcher.RequestMatcher#matches(javax.
		 * servlet.http.HttpServletRequest)
		 */
		@Override
		public boolean matches(HttpServletRequest request) {
			return !this.allowedMethods.contains(request.getMethod());
		}
	}
}
