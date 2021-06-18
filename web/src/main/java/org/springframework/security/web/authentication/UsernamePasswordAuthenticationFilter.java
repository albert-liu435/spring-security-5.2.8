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

package org.springframework.security.web.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * https://andyboke.blog.csdn.net/article/details/84728228
 * <p>
 * 该过滤器会拦截用户请求，看它是否是一个来自用户名/密码表单登录页面提交的用户登录认证请求，缺省使用的匹配模式是:POST /login。缺省情况下，如果是用户登录认证请求，该请求就不会在整个filter chain中继续传递了，而是会被当前过滤器处理并进入响应用户阶段。
 * <p>
 * 具体用户登录认证处理逻辑是这样的，它会调用所指定的AuthenticationManager认证所提交的用户名/密码。
 * <p>
 * 如果认证成功，则会 ：
 * <p>
 * 调用所设置的SessionAuthenticationStrategy会话认证策略;
 * <p>
 * 针对Servlet 3.1+,缺省所使用的SessionAuthenticationStrategy是一个ChangeSessionIdAuthenticationStrategy和CsrfAuthenticationStrategy组合。ChangeSessionIdAuthenticationStrategy会为登录的用户创建一个新的session，而CsrfAuthenticationStrategy会创建新的csrf token用于CSRF保护。
 * <p>
 * 经过完全认证的Authentication对象设置到SecurityContextHolder中的SecurityContext上;
 * <p>
 * 如果请求要求了Remember Me,进行相应记录;
 * <p>
 * 发布事件InteractiveAuthenticationSuccessEvent;
 * <p>
 * 获取并跳转到目标跳转页面；
 * <p>
 * 缺省情况下，该跳转策略是SavedRequestAwareAuthenticationSuccessHandler。
 * <p>
 * 如果有保存的请求,则获取保存的请求，跳转到相应的请求地址;
 * 一般在未登录用户直接访问受保护页面时会出现该情况：先被跳转到登录页面，登录完成过后再被跳转到原始请求页面
 * <p>
 * alwaysUseDefaultTargetUrl为true则总是会跳到指定的defaultTargetUrl;
 * 注意: defaultTargetUrl 也是可以设置的，如果不设置，其值缺省为/
 * <p>
 * alwaysUseDefaultTargetUrl为false则
 * 看请求参数中是否含有名称为配置参数targetUrlParameter值的参数，如果有，跳转到它定义的地址；
 * 否则如果指定了useReferer，尝试使用请求头部Referer作为目标跳转地址;
 * 否则使用defaultTargetUrl作为目标跳转地址;
 * <p>
 * <p>
 * <p>
 * <p>
 * 表单提交了 username 和 password，被封装成 token 进行一系列的认证，便是主要通过这个过滤器完成的，在表单认证的方法中，这是最最关键的过滤器。
 * <p>
 * https://felord.cn/usernamePasswordAuthenticationFilter.html
 * Http登录认证由过滤器UsernamePasswordAuthenticationFilter 进行处理
 * <p>
 * UsernamePasswordAuthenticationFilter 继承于AbstractAuthenticationProcessingFilter（另文分析）。它的作用是拦截登录请求并获取账号和密码，然后把账号密码封装到认证凭据
 * UsernamePasswordAuthenticationToken中，然后把凭据交给特定配置的AuthenticationManager去作认证
 * <p>
 * <p>
 * <p>
 * 根据上面的流程，我们理解了UsernamePasswordAuthenticationFilter工作流程后可以做这些事情：
 * <p>
 * 定制我们的登录请求URI和请求方式。
 * <p>
 * 登录请求参数的格式定制化，比如可以使用JSON格式提交甚至几种并存。
 * <p>
 * 将用户名和密码封装入凭据UsernamePasswordAuthenticationToken，定制业务场景需要的特殊凭据。
 * <p>
 * Processes an authentication form submission. Called
 * {@code AuthenticationProcessingFilter} prior to Spring Security 3.0.
 * <p>
 * Login forms must present two parameters to this filter: a username and password. The
 * default parameter names to use are contained in the static fields
 * {@link #SPRING_SECURITY_FORM_USERNAME_KEY} and
 * {@link #SPRING_SECURITY_FORM_PASSWORD_KEY}. The parameter names can also be changed by
 * setting the {@code usernameParameter} and {@code passwordParameter} properties.
 * <p>
 * This filter by default responds to the URL {@code /login}.
 *
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Luke Taylor
 * @since 3.0
 */
public class UsernamePasswordAuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {
	// ~ Static fields/initializers
	// =====================================================================================
	// 默认取账户名、密码的key
	// 用户名/密码登录表单中用户名字段缺省使用的名称
	public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
	public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
	// 可以通过对应的set方法修改
	private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
	private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
	// 默认只支持 POST 请求
	private boolean postOnly = true;

	// ~ Constructors
	// ===================================================================================================
	//  初始化一个用户密码 认证过滤器  默认的登录uri 是 /login 请求方式是POST
	public UsernamePasswordAuthenticationFilter() {
		// 缺省匹配用户请求 POST /login，认为该请求是用户名/密码表单登录验证请求
		super(new AntPathRequestMatcher("/login", "POST"));
	}

	// ~ Methods
	// ========================================================================================================
// 实现其父类 AbstractAuthenticationProcessingFilter 提供的钩子方法 用去尝试认证
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		// 判断请求方式是否是POST
		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException(
					"Authentication method not supported: " + request.getMethod());
		}
		// 先去 HttpServletRequest 对象中获取账号名、密码
		// 从请求中获取用户名/密码，也就是用户填写在用户名/密码登录表单中的这些信息
		String username = obtainUsername(request);
		String password = obtainPassword(request);

		if (username == null) {
			username = "";
		}

		if (password == null) {
			password = "";
		}
		// 注意，这里对用户名做了trim操作，一般理解，就是去除了前后的空格
		username = username.trim();
		// 然后把账号名、密码封装到 一个认证Token对象中，这是就是一个通行证，但是这时的状态时不可信的，一旦通过认证就变为可信的
		// 根据用户提供的用户名/密码信息构建一个认证token
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password);

		// Allow subclasses to set the "details" property
		// 会将 HttpServletRequest 中的一些细节 request.getRemoteAddr()   request.getSession 存入的到Token中
		setDetails(request, authRequest);
		// 然后 使用 父类中的 AuthenticationManager 对Token 进行认证
		//AuthenticationManager中实际完成身份验证任务并不是AuthenticationManager它自己身。而是将相关的任务针对每一种身份验证协议的AuthenticationProvider去完成相关的身份验证工作
		//
		//作者：AkiraPan
		//链接：https://www.jianshu.com/p/97ce9b071505
		//来源：简书
		//著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
		// 交给 authenticationManager执行真正的用户身份认证
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	/**
	 * 获取请求中的密码
	 * Enables subclasses to override the composition of the password, such as by
	 * including additional values and a separator.
	 * <p>
	 * This might be used for example if a postcode/zipcode was required in addition to
	 * the password. A delimiter such as a pipe (|) should be used to separate the
	 * password and extended value(s). The <code>AuthenticationDao</code> will need to
	 * generate the expected password in a corresponding manner.
	 * </p>
	 *
	 * @param request so that request attributes can be retrieved
	 * @return the password that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	@Nullable
	protected String obtainPassword(HttpServletRequest request) {
		return request.getParameter(passwordParameter);
	}

	/**
	 * 获取请求中的用户名
	 * // 获取账户很重要 如果你想改变获取密码的方式要么在此处重写，要么通过自定义一个前置的过滤器保证能此处能get到
	 * Enables subclasses to override the composition of the username, such as by
	 * including additional values and a separator.
	 *
	 * @param request so that request attributes can be retrieved
	 * @return the username that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	@Nullable
	protected String obtainUsername(HttpServletRequest request) {
		return request.getParameter(usernameParameter);
	}

	/**
	 * 为凭据设置一些请求细节
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request     that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 *                    set
	 */
	protected void setDetails(HttpServletRequest request,
			UsernamePasswordAuthenticationToken authRequest) {
		//如这里可以通过实现AuthenticationDetailsSource来设置一些需要的详细信息
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * 设置账户参数的key
	 * Sets the parameter name which will be used to obtain the username from the login
	 * request.
	 *
	 * @param usernameParameter the parameter name. Defaults to "username".
	 */
	public void setUsernameParameter(String usernameParameter) {
		Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
		this.usernameParameter = usernameParameter;
	}

	/**
	 * // 设置密码参数的key
	 * Sets the parameter name which will be used to obtain the password from the login
	 * request..
	 *
	 * @param passwordParameter the parameter name. Defaults to "password".
	 */
	public void setPasswordParameter(String passwordParameter) {
		Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
		this.passwordParameter = passwordParameter;
	}

	/**
	 * 认证的请求方式是只支持POST请求
	 * 设置是否仅仅接受HTTP POST用户名/密码登录验证表单请求，缺省为true，表示必须使用HTTP POST。
	 * <p>
	 * Defines whether only HTTP POST requests will be allowed by this filter. If set to
	 * true, and an authentication request is received which is not a POST request, an
	 * exception will be raised immediately and authentication will not be attempted. The
	 * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
	 * authentication.
	 * <p>
	 * Defaults to <tt>true</tt> but may be overridden by subclasses.
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

	public final String getUsernameParameter() {
		return usernameParameter;
	}

	public final String getPasswordParameter() {
		return passwordParameter;
	}
}
