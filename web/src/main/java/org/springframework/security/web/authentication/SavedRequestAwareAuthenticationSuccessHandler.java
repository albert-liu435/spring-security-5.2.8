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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.util.StringUtils;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

/**
 * 框架默认的 AuthenticationSuccessHandler 为 SavedRequestAwareAuthenticationSuccessHandler。
 * https://blog.csdn.net/liuminglei1987/article/details/106936595
 * <p>
 * 这个类会记住用户上一次请求的资源路径，用来进行登录成功之后跳转到上面页面的路径
 * An authentication success strategy which can make use of the
 * {@link org.springframework.security.web.savedrequest.DefaultSavedRequest} which may have been stored in the session by the
 * {@link ExceptionTranslationFilter}. When such a request is intercepted and requires
 * authentication, the request data is stored to record the original destination before
 * the authentication process commenced, and to allow the request to be reconstructed when
 * a redirect to the same URL occurs. This class is responsible for performing the
 * redirect to the original URL if appropriate.
 * <p>
 * 成功的身份验证后，它将根据以下场景决定重定向目标：
 * <p>
 * Following a successful authentication, it decides on the redirect destination, based on
 * the following scenarios:
 * <ul>
 * <li>
 * If the {@code alwaysUseDefaultTargetUrl} property is set to true, the
 * {@code defaultTargetUrl} will be used for the destination. Any
 * {@code DefaultSavedRequest} stored in the session will be removed.</li>
 * <li>
 * If the {@code targetUrlParameter} has been set on the request, the value will be used
 * as the destination. Any {@code DefaultSavedRequest} will again be removed.</li>
 * <li>
 * If a {@link org.springframework.security.web.savedrequest.SavedRequest} is found in the {@code RequestCache} (as set by the
 * {@link ExceptionTranslationFilter} to record the original destination before the
 * authentication process commenced), a redirect will be performed to the Url of that
 * original destination. The {@code SavedRequest} object will remain cached and be picked
 * up when the redirected request is received (See
 * <a href="{@docRoot}/org/springframework/security/web/savedrequest/SavedRequestAwareWrapper.html">SavedRequestAwareWrapper</a>).
 * </li>
 * <li>
 * If no {@link org.springframework.security.web.savedrequest.SavedRequest} is found, it will delegate to the base class.</li>
 * </ul>
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SavedRequestAwareAuthenticationSuccessHandler extends
		SimpleUrlAuthenticationSuccessHandler {
	protected final Log logger = LogFactory.getLog(this.getClass());

	private RequestCache requestCache = new HttpSessionRequestCache();

	/**
	 * 用于处理认证成功之后不的后续流程
	 *
	 * @param request
	 * @param response
	 * @param authentication
	 * @throws ServletException
	 * @throws IOException
	 */
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication)
			throws ServletException, IOException {
		//获取SavedRequest
		//判断当前Request是否缓存（另外需要看 Spring Security 是否开启了 Request 缓存，默认是开启的）。
		SavedRequest savedRequest = requestCache.getRequest(request, response);
		//如果 Spring Security 关闭了 Request 缓存，或者当前 Request 并没有被缓存，那么就走默认的认证成功逻辑。
		if (savedRequest == null) {
			super.onAuthenticationSuccess(request, response, authentication);

			return;
		}
		//获取请求参数名称
		String targetUrlParameter = getTargetUrlParameter();
		//否则，继续根据 alwaysUseDefaultTargetUrl 判断是否永远重定向到 defaultTargetUrl；亦或是，如果配置了targetUrlParameter 且当前 request 存在该参数值，那么，从缓存中移除当前request，并走默认的认证成功逻辑。
		//简而言之，就是如果 alwaysUseDefaultTargetUrl 为true，则重定向 defaultTargetUrl；如果配置了 targetUrlParameter 且其对应的值不为空，则重定向到该地址；如果配置的 useReferer 为 true 且其值不为空，则重定向到该地址；否则，则重定向到 defaultTargetUrl。
		if (isAlwaysUseDefaultTargetUrl()
				|| (targetUrlParameter != null && StringUtils.hasText(request
				.getParameter(targetUrlParameter)))) {
			//
			requestCache.removeRequest(request, response);
			super.onAuthenticationSuccess(request, response, authentication);

			return;
		}

		//删除可能在身份验证过程中存储在会话中的与身份验证相关的临时数据。
		clearAuthenticationAttributes(request);

		// Use the DefaultSavedRequest URL
		//获取本次请求的完整请求 如：http://localhost:8081/hello
		//以上情况都不满足，即 Spring Security 开启了 Request 缓存，且当前 request 被缓存了，框架即重定向到缓存 request 对应的地址。
		String targetUrl = savedRequest.getRedirectUrl();
		logger.debug("Redirecting to DefaultSavedRequest Url: " + targetUrl);
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}
}
