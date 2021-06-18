/*
 * Copyright 2004-2016 the original author or authors.
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
package org.springframework.security.web.access;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import org.springframework.context.support.MessageSourceAccessor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * https://andyboke.blog.csdn.net/article/details/84930208
 * <p>
 * 该过滤器的作用是处理过滤器链中发生的 AccessDeniedException 和 AuthenticationException 异常，将它们转换成相应的HTTP响应。
 * <p>
 * 当检测到 AuthenticationException 异常时，该过滤器会启动 authenticationEntryPoint,也就是启动认证流程。
 * <p>
 * 当检测到 AccessDeniedException 异常时，该过滤器先判断当前用户是否为匿名访问或者Remember Me访问。如果是这两种情况之一，会启动 authenticationEntryPoint逻辑。如果安全配置开启了用户名/密码表单认证，通常这个authenticationEntryPoint会对应到一个LoginUrlAuthenticationEntryPoint。它执行时会将用户带到登录页面，开启登录认证流程。
 * <p>
 * 如果不是匿名访问或者Remember Me访问，接下来的处理会交给一个 AccessDeniedHandler 来完成。缺省情况下，这个 AccessDeniedHandler 的实现类是 AccessDeniedHandlerImpl，它会:
 * <p>
 * 请求添加HTTP 403异常属性,记录相应的异常;
 * 然后往写入响应HTTP状态码403;
 * 并foward到相应的错误页面。
 * 使用该过滤器必须要设置以下属性:
 * <p>
 * authenticationEntryPoint:用于启动认证流程的处理器(handler)
 * requestCache:认证过程中涉及到保存请求时使用的请求缓存策略，缺省情况下是基于session的HttpSessionRequestCache
 * <p>
 * <p>
 * 用于处理异常的过滤器
 * 直译成异常翻译过滤器，还是比较形象的，这个过滤器本身不处理异常，而是将认证过程中出现的异常交给内部维护的一些类去处理
 * <p>
 * ExceptionTranslationFilter 异常转换过滤器位于整个 springSecurityFilterChain 的后方，用来转换整个链路中出现的异常，将其转化，顾名思义，转化以意味本身并不处理。一般其只处理两大类异常：AccessDeniedException 访问异常和 AuthenticationException 认证异常。
 * <p>
 * 这个过滤器非常重要，因为它将 Java 中的异常和 HTTP 的响应连接在了一起，这样在处理异常时，我们不用考虑密码错误该跳到什么页面，账号锁定该如何，只需要关注自己的业务逻辑，抛出相应的异常便可。
 * 如果该过滤器检测到 AuthenticationException，则将会交给内部的 AuthenticationEntryPoint 去处理，如果检测到 AccessDeniedException，需要先判断当前用户是不是匿名用户，如果是匿名访问，则和前面一样运行
 * AuthenticationEntryPoint，否则会委托给 AccessDeniedHandler 去处理，而 AccessDeniedHandler 的默认实现，是 AccessDeniedHandlerImpl。所以 ExceptionTranslationFilter 内部的 AuthenticationEntryPoint 是至关重要的，顾名思义：认证的入口点。
 * <p>
 * Handles any <code>AccessDeniedException</code> and <code>AuthenticationException</code>
 * thrown within the filter chain.
 * <p>
 * This filter is necessary because it provides the bridge between Java exceptions and
 * HTTP responses. It is solely concerned with maintaining the user interface. This filter
 * does not do any actual security enforcement.
 * <p>
 * If an {@link AuthenticationException} is detected, the filter will launch the
 * <code>authenticationEntryPoint</code>. This allows common handling of authentication
 * failures originating from any subclass of
 * {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor}.
 * <p>
 * If an {@link AccessDeniedException} is detected, the filter will determine whether or
 * not the user is an anonymous user. If they are an anonymous user, the
 * <code>authenticationEntryPoint</code> will be launched. If they are not an anonymous
 * user, the filter will delegate to the
 * {@link org.springframework.security.web.access.AccessDeniedHandler}. By default the
 * filter will use {@link org.springframework.security.web.access.AccessDeniedHandlerImpl}.
 * <p>
 * To use this filter, it is necessary to specify the following properties:
 * <ul>
 * <li><code>authenticationEntryPoint</code> indicates the handler that should commence
 * the authentication process if an <code>AuthenticationException</code> is detected. Note
 * that this may also switch the current protocol from http to https for an SSL login.</li>
 * <li><tt>requestCache</tt> determines the strategy used to save a request during the
 * authentication process in order that it may be retrieved and reused once the user has
 * authenticated. The default implementation is {@link HttpSessionRequestCache}.</li>
 * </ul>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class ExceptionTranslationFilter extends GenericFilterBean {

	// ~ Instance fields
	// ================================================================================================

	private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
	//认证入口点
	private AuthenticationEntryPoint authenticationEntryPoint;
	// 用于判断一个Authentication是否Anonymous,Remember Me,
	// 缺省使用 AuthenticationTrustResolverImpl
	private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
	// 用于分析一个Throwable抛出的原因，使用本类自定义的嵌套类DefaultThrowableAnalyzer，
	// 主要是加入了对ServletException的分析
	private ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
	// 请求缓存，缺省使用HttpSessionRequestCache，在遇到异常启动认证过程时会用到,
	// 因为要先把原始请求缓存下来，一旦认证成功结果，需要把原始请求提出重新跳转到相应URL
	private RequestCache requestCache = new HttpSessionRequestCache();

	private final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint) {
		this(authenticationEntryPoint, new HttpSessionRequestCache());
	}

	public ExceptionTranslationFilter(AuthenticationEntryPoint authenticationEntryPoint,
			RequestCache requestCache) {
		Assert.notNull(authenticationEntryPoint,
				"authenticationEntryPoint cannot be null");
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
		this.requestCache = requestCache;
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(authenticationEntryPoint,
				"authenticationEntryPoint must be specified");
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
// 在任何请求到达时不做任何操作，直接放行，继续filter chain的执行，
		// 但是使用一个 try-catch 来捕获filter chain中接下来会发生的各种异常，
		// 重点关注其中的以下异常，其他异常继续向外抛出 :
		// AuthenticationException : 认证失败异常,通常因为认证信息错误导致
		// AccessDeniedException : 访问被拒绝异常，通常因为权限不足导致
		try {
			chain.doFilter(request, response);

			logger.debug("Chain processed normally");
		} catch (IOException ex) {
			throw ex;
		} catch (Exception ex) {
			// Try to extract a SpringSecurityException from the stacktrace
			//获取Throwable
			Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
			//获取异常类型
			// 判断异常是否是AuthenticationException
			// 检测ex是否由AuthenticationException或者AccessDeniedException异常导致
			RuntimeException ase = (AuthenticationException) throwableAnalyzer
					.getFirstThrowableOfType(AuthenticationException.class, causeChain);

			if (ase == null) {
				// 判断异常是否是AccessDeniedException
				ase = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(
						AccessDeniedException.class, causeChain);
			}

			if (ase != null) {
				if (response.isCommitted()) {
					throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", ex);
				}
				// 如果是AccessDeniedException 或者AuthenticationException则进入如下方法
				handleSpringSecurityException(request, response, chain, ase);
			} else {
				// Rethrow ServletExceptions and RuntimeExceptions as-is
				if (ex instanceof ServletException) {
					throw (ServletException) ex;
				} else if (ex instanceof RuntimeException) {
					throw (RuntimeException) ex;
				}

				// Wrap other Exceptions. This shouldn't actually happen
				// as we've already covered all the possibilities for doFilter
				throw new RuntimeException(ex);
			}
		}
	}

	public AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return authenticationEntryPoint;
	}

	protected AuthenticationTrustResolver getAuthenticationTrustResolver() {
		return authenticationTrustResolver;
	}

	/**
	 * // 处理异常转换的核心方法
	 *
	 * @param request
	 * @param response
	 * @param chain
	 * @param exception
	 * @throws IOException
	 * @throws ServletException
	 */
	private void handleSpringSecurityException(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain, RuntimeException exception)
			throws IOException, ServletException {
		if (exception instanceof AuthenticationException) {
			logger.debug(
					"Authentication exception occurred; redirecting to authentication entry point",
					exception);
			//默认 重定向到登录端点
			sendStartAuthentication(request, response, chain,
					(AuthenticationException) exception);
		} else if (exception instanceof AccessDeniedException) {
			//获取认证token
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			//判断是否为匿名token
			if (authenticationTrustResolver.isAnonymous(authentication) || authenticationTrustResolver.isRememberMe(authentication)) {
				logger.debug(
						"Access is denied (user is " + (authenticationTrustResolver.isAnonymous(authentication) ? "anonymous" : "not fully authenticated") + "); redirecting to authentication entry point",
						exception);
				// 默认重定向到登录端点
				sendStartAuthentication(
						request,
						response,
						chain,
						new InsufficientAuthenticationException(
								messages.getMessage(
										"ExceptionTranslationFilter.insufficientAuthentication",
										"Full authentication is required to access this resource")));
			} else {
				logger.debug(
						"Access is denied (user is not anonymous); delegating to AccessDeniedHandler",
						exception);
				// 交给 accessDeniedHandler 处理
				accessDeniedHandler.handle(request, response,
						(AccessDeniedException) exception);
			}
		}
	}

	/**
	 * 重定向到登录端点
	 *
	 * @param request
	 * @param response
	 * @param chain
	 * @param reason
	 * @throws ServletException
	 * @throws IOException
	 */
	protected void sendStartAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain,
			AuthenticationException reason) throws ServletException, IOException {
		// SEC-112: Clear the SecurityContextHolder's Authentication, as the
		// existing Authentication is no longer considered valid
		//设置为null
		SecurityContextHolder.getContext().setAuthentication(null);
		//缓存当前的请求
		requestCache.saveRequest(request, response);
		logger.debug("Calling Authentication entry point.");
		//跳转到登录认证页面
		authenticationEntryPoint.commence(request, response, reason);
	}

	public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "AccessDeniedHandler required");
		this.accessDeniedHandler = accessDeniedHandler;
	}

	public void setAuthenticationTrustResolver(
			AuthenticationTrustResolver authenticationTrustResolver) {
		Assert.notNull(authenticationTrustResolver,
				"authenticationTrustResolver must not be null");
		this.authenticationTrustResolver = authenticationTrustResolver;
	}

	public void setThrowableAnalyzer(ThrowableAnalyzer throwableAnalyzer) {
		Assert.notNull(throwableAnalyzer, "throwableAnalyzer must not be null");
		this.throwableAnalyzer = throwableAnalyzer;
	}

	/**
	 * Default implementation of <code>ThrowableAnalyzer</code> which is capable of also
	 * unwrapping <code>ServletException</code>s.
	 */
	private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
		/**
		 * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
		 */
		protected void initExtractorMap() {
			super.initExtractorMap();

			registerExtractor(ServletException.class, throwable -> {
				ThrowableAnalyzer.verifyThrowableHierarchy(throwable,
						ServletException.class);
				return ((ServletException) throwable).getRootCause();
			});
		}

	}

}
