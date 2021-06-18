/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.rememberme;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * https://andyboke.blog.csdn.net/article/details/84937412
 * <p>
 * 缺省情况下，如果安全配置开启了Remember Me机制，用户在登录界面上会看到Remember Me选择框，如果用户选择了该选择框，会导致生成一个名为remember-me,属性httpOnly为true的cookie，其值是一个RememberMe token。
 * <p>
 * RememberMe token是一个Base64编码的字符串，解码后格式为{用户名}:{Token过期时间戳}:{Token签名摘要},比如:admin:1545787408479:d0b0e7a53960e94b521bee3f02ba0bf5
 * <p>
 * 而该过滤器在每次请求到达时会检测SecurityContext属性Authentication是否已经设置。如果没有设置，会进入该过滤器的职责逻辑。它尝试获取名为remember-me的cookie,获取到的话会认为这是一次Remember Me登录尝试，从中分析出用户名,Token过期时间戳，签名摘要，针对用户库验证这些信息，认证通过的话，就会往SecurityContext里面设置Authentication为一个针对请求中所指定用户的RememberMeAuthenticationToken。
 * <p>
 * 认证成功的话，也会向应用上下文发布事件InteractiveAuthenticationSuccessEvent。
 * <p>
 * 默认情况下不管认证成功还是失败，请求都会被继续执行。
 * <p>
 * 不过也可以指定一个AuthenticationSuccessHandler给当前过滤器，这样当Remember Me登录认证成功时，处理委托给该AuthenticationSuccessHandler,而不再继续原请求的处理。利用这种机制，可以为Remember Me登录认证成功指定特定的跳转地址。
 * <p>
 * Remember Me登录认证成功并不代表用户一定可以访问到目标页面，因为如果Remember Me登录认证成功对应用户访问权限级别为isRememberMe，而目标页面需要更高的访问权限级别fullyAuthenticated,这时候请求最终会被拒绝访问目标页面，原因是权限不足(虽然认证通过)。
 * <p>
 * 如果你想观察该过滤器的行为，可以这么做：
 * <p>
 * 在配置中开启Remember Me机制，则此过滤器会被使用;
 * 启动应用，打开浏览器,提供正确的用户名密码，选择Remember Me选项,然后提交完成一次成功的登录;
 * 关闭整个浏览器;
 * 重新打开刚刚关闭的浏览器;
 * 直接访问某个受rememberMe访问级别保护的页面，你会看到该过滤器的职责逻辑被执行，目标页面可以访问。
 * 注意 : 这里如果访问某个受fullyAuthenticated访问级别保护的页面，目标页面则不能访问，浏览器会被跳转到登录页面
 * Detects if there is no {@code Authentication} object in the {@code SecurityContext},
 * and populates the context with a remember-me authentication token if a
 * {@link RememberMeServices} implementation so requests.
 * <p>
 * Concrete {@code RememberMeServices} implementations will have their
 * {@link RememberMeServices#autoLogin(HttpServletRequest, HttpServletResponse)} method
 * called by this filter. If this method returns a non-null {@code Authentication} object,
 * it will be passed to the {@code AuthenticationManager}, so that any
 * authentication-specific behaviour can be achieved. The resulting {@code Authentication}
 * (if successful) will be placed into the {@code SecurityContext}.
 * <p>
 * If authentication is successful, an {@link InteractiveAuthenticationSuccessEvent} will
 * be published to the application context. No events will be published if authentication
 * was unsuccessful, because this would generally be recorded via an
 * {@code AuthenticationManager}-specific application event.
 * <p>
 * Normally the request will be allowed to proceed regardless of whether authentication
 * succeeds or fails. If some control over the destination for authenticated users is
 * required, an {@link AuthenticationSuccessHandler} can be injected
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class RememberMeAuthenticationFilter extends GenericFilterBean implements
		ApplicationEventPublisherAware {

	// ~ Instance fields
	// ================================================================================================
	//
	private ApplicationEventPublisher eventPublisher;
	//策略接口，用于处理成功的身份验证逻辑
	private AuthenticationSuccessHandler successHandler;
	//用来处理身份认证的请求
	private AuthenticationManager authenticationManager;
	//由能够提供“记住我”服务的类实现。
	private RememberMeServices rememberMeServices;

	public RememberMeAuthenticationFilter(AuthenticationManager authenticationManager,
			RememberMeServices rememberMeServices) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(rememberMeServices, "rememberMeServices cannot be null");
		this.authenticationManager = authenticationManager;
		this.rememberMeServices = rememberMeServices;
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(authenticationManager, "authenticationManager must be specified");
		Assert.notNull(rememberMeServices, "rememberMeServices must be specified");
	}

	/**
	 * 过滤器
	 *
	 * @param req
	 * @param res
	 * @param chain
	 * @throws IOException
	 * @throws ServletException
	 */
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		//前面没有Filter进行认证，则采用下面的认证方式
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			// 如果SecurityContext中authentication为空则尝试 remember me 自动认证,
			// 缺省情况下这里rememberMeServices会是一个TokenBasedRememberMeServices,
			// 其自动 remember me 认证过程如下:
			// 1. 获取 cookie remember-me 的值 , 一个base64 编码串;
			// 2. 从上面cookie之中解析出信息:用户名，token 过期时间，token 签名
			// 3. 检查用户是否存在，token是否过期，token 签名是否一致,
			// 上面三个步骤都通过的情况下再检查一下账号是否锁定，过期，禁用，密码过期等现象,
			// 如果上面这些验证都通过，则认为认证成功，会构造一个
			// RememberMeAuthenticationToken并返回
			// 上面的认证失败会有rememberMeAuth==null
			Authentication rememberMeAuth = rememberMeServices.autoLogin(request,
					response);

			//如果不为null的话就尝试进行认证
			if (rememberMeAuth != null) {
				// Attempt authenticaton via AuthenticationManager
				try {
					// 如果上面的 Remember Me 认证成功，则需要使用 authenticationManager
					// 认证该rememberMeAuth
					rememberMeAuth = authenticationManager.authenticate(rememberMeAuth);

					// Store to SecurityContextHolder
					// 将认证成功的rememberMeAuth放到SecurityContextHolder中的SecurityContext
					SecurityContextHolder.getContext().setAuthentication(rememberMeAuth);
				// 成功时的其他操作:空方法，其实没有其他在这里做
					onSuccessfulAuthentication(request, response, rememberMeAuth);

					if (logger.isDebugEnabled()) {
						logger.debug("SecurityContextHolder populated with remember-me token: '"
								+ SecurityContextHolder.getContext().getAuthentication()
								+ "'");
					}

					// Fire event
					if (this.eventPublisher != null) {
						// 发布事件 InteractiveAuthenticationSuccessEvent 到应用上下文
						eventPublisher
								.publishEvent(new InteractiveAuthenticationSuccessEvent(
										SecurityContextHolder.getContext()
												.getAuthentication(), this.getClass()));
					}

					if (successHandler != null) {
						// 如果指定了 successHandler ,则调用它，
						// 缺省情况下这个 successHandler  为 null
						successHandler.onAuthenticationSuccess(request, response,
								rememberMeAuth);
						// 如果指定了 successHandler，在它调用之后，不再继续 filter chain 的执行

						return;
					}

				} catch (AuthenticationException authenticationException) {
					// Remember Me 认证失败的情况
					if (logger.isDebugEnabled()) {
						logger.debug(
								"SecurityContextHolder not populated with remember-me token, as "
										+ "AuthenticationManager rejected Authentication returned by RememberMeServices: '"
										+ rememberMeAuth
										+ "'; invalidating remember-me token",
								authenticationException);
					}
					// rememberMeServices 的认证失败处理

					rememberMeServices.loginFail(request, response);
					// 空方法，这里什么都不做

					onUnsuccessfulAuthentication(request, response,
							authenticationException);
				}
			}
			// 继续 filter chain 执行
			chain.doFilter(request, response);
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("SecurityContextHolder not populated with remember-me token, as it already contained: '"
						+ SecurityContextHolder.getContext().getAuthentication() + "'");
			}

			chain.doFilter(request, response);
		}
	}

	/**
	 * Called if a remember-me token is presented and successfully authenticated by the
	 * {@code RememberMeServices} {@code autoLogin} method and the
	 * {@code AuthenticationManager}.
	 */
	protected void onSuccessfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, Authentication authResult) {
	}

	/**
	 * Called if the {@code AuthenticationManager} rejects the authentication object
	 * returned from the {@code RememberMeServices} {@code autoLogin} method. This method
	 * will not be called when no remember-me token is present in the request and
	 * {@code autoLogin} reurns null.
	 */
	protected void onUnsuccessfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException failed) {
	}

	public RememberMeServices getRememberMeServices() {
		return rememberMeServices;
	}

	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}

	/**
	 * 缺省情况下，Remember Me 登录认证成功时filter chain会继续执行。但是也允许指定一个
	 * AuthenticationSuccessHandler , 这样就可以控制 Remember Me 登录认证成功时的目标
	 * 跳转地址(当然会忽略原始的请求目标)。
	 * Allows control over the destination a remembered user is sent to when they are
	 * successfully authenticated. By default, the filter will just allow the current
	 * request to proceed, but if an {@code AuthenticationSuccessHandler} is set, it will
	 * be invoked and the {@code doFilter()} method will return immediately, thus allowing
	 * the application to redirect the user to a specific URL, regardless of whatthe
	 * original request was for.
	 *
	 * @param successHandler the strategy to invoke immediately before returning from
	 *                       {@code doFilter()}.
	 */
	public void setAuthenticationSuccessHandler(
			AuthenticationSuccessHandler successHandler) {
		Assert.notNull(successHandler, "successHandler cannot be null");
		this.successHandler = successHandler;
	}

}
