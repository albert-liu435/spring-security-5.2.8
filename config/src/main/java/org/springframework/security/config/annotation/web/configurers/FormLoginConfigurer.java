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
package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.ForwardAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * https://andyboke.blog.csdn.net/article/details/91357155
 * <p>
 * <p>
 * 作为一个配置HttpSecurity的SecurityConfigurer,FormLoginConfigurer的配置任务如下 :
 * <p>
 * 配置如下安全过滤器Filter
 * <p>
 * UsernamePasswordAuthenticationFilter
 * 创建的共享对象
 * <p>
 * AuthenticationEntryPoint
 * FormLoginConfigurer使用到的共享对象有 :
 * <p>
 * AuthenticationManager
 * RememberMeServices
 * SessionAuthenticationStrategy
 * DefaultLoginPageGeneratingFilter
 * FormLoginConfigurer允许使用者做如下配置 :
 * <p>
 * 设置登录页面URL – #loginPage
 * <p>
 * 缺省值为 /login。
 * 该方法没有被调用，并且使用了WebSecurityConfigurerAdapter时，会产生一个缺省的登录页面在缺省登录URL /login上。
 * 如果使用该方法指定了一个跟缺省值不同的登录页面URL,或者没有配合使用WebSecurityConfigurerAdapter,那么使用者也必须在指定的登录页面URL上提供自己的登录页面实现。
 * 一般情况下，所实现的登录页面必须提供一个登录表单，符合以下条件 :
 * <p>
 * 必须发起HTTP POST请求；
 * 必须提交到登录提交处理URL,也就是#createLoginProcessingUrlMatcher所设置；
 * 用户名字段名称使用#usernameParameter所设置值；
 * 密码字段名称使用#passwordParameter所设置值；
 * 设置登录提交处理URL – #createLoginProcessingUrlMatcher
 * <p>
 * 设置登录成功跳转页面URL – #successForwardUrl
 * <p>
 * 设置登录失败跳转页面URL – #failureForwardUrl
 * <p>
 * 设置登录页面中用户名字段名称 – #usernameParameter
 * <p>
 * 缺省值 : username
 * <p>
 * 设置登录页面中密码字段名称 – #passwordParameter
 * <p>
 * 缺省值 : password
 * <p>
 * <p>
 * 添加表单身份认证，如果没有配置loginPage,就是用默认的表单，默认添加UsernamePasswordAuthenticationFilter过滤器
 * <p>
 * https://felord.cn/spring-security-login.html
 * Adds form based authentication. All attributes have reasonable defaults making all
 * parameters are optional. If no {@link #loginPage(String)} is specified, a default login
 * page will be generated by the framework.
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link UsernamePasswordAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * The following shared objects are populated
 *
 * <ul>
 * <li>{@link AuthenticationEntryPoint}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 * <p>
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link org.springframework.security.authentication.AuthenticationManager}</li>
 * <li>{@link RememberMeServices} - is optionally used. See {@link RememberMeConfigurer}
 * </li>
 * <li>{@link SessionAuthenticationStrategy} - is optionally used. See
 * {@link SessionManagementConfigurer}</li>
 * <li>{@link DefaultLoginPageGeneratingFilter} - if present will be populated with
 * information from the configuration</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Shazin Sadakath
 * @since 3.2
 */
public final class FormLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractAuthenticationFilterConfigurer<H, FormLoginConfigurer<H>, UsernamePasswordAuthenticationFilter> {

	/**
	 * Creates a new instance
	 *
	 * @see HttpSecurity#formLogin()
	 */
	public FormLoginConfigurer() {
		super(new UsernamePasswordAuthenticationFilter(), null);
		//这段代码可以不需要，因为默认就是这个样子
		usernameParameter("username");
		passwordParameter("password");
	}

	/**
	 * 指定在需要登录时向用户发送的URL,
	 * 登录 页面而并不是接口，对于前后分离模式需要我们进行改造 默认为 /login。
	 * <p>
	 * Specifies the URL to send users to if login is required. If used with
	 * {@link WebSecurityConfigurerAdapter} a default login page will be generated when
	 * this attribute is not specified.
	 * </p>
	 *
	 * <p>
	 * If a URL is specified or this is not being used in conjuction with
	 * {@link WebSecurityConfigurerAdapter}, users are required to process the specified
	 * URL to generate a login page. In general, the login page should create a form that
	 * submits a request with the following requirements to work with
	 * {@link UsernamePasswordAuthenticationFilter}:
	 * </p>
	 *
	 * <ul>
	 * <li>It must be an HTTP POST</li>
	 * <li>It must be submitted to {@link #loginProcessingUrl(String)}</li>
	 * <li>It should include the username as an HTTP parameter by the name of
	 * {@link #usernameParameter(String)}</li>
	 * <li>It should include the password as an HTTP parameter by the name of
	 * {@link #passwordParameter(String)}</li>
	 * </ul>
	 *
	 * <h2>Example login.jsp</h2>
	 * <p>
	 * Login pages can be rendered with any technology you choose so long as the rules
	 * above are followed. Below is an example login.jsp that can be used as a quick start
	 * when using JSP's or as a baseline to translate into another view technology.
	 *
	 * <pre>
	 * <!-- loginProcessingUrl should correspond to FormLoginConfigurer#loginProcessingUrl. Don't forget to perform a POST -->
	 * &lt;c:url value="/login" var="loginProcessingUrl"/&gt;
	 * &lt;form action="${loginProcessingUrl}" method="post"&gt;
	 *    &lt;fieldset&gt;
	 *        &lt;legend&gt;Please Login&lt;/legend&gt;
	 *        &lt;!-- use param.error assuming FormLoginConfigurer#failureUrl contains the query parameter error --&gt;
	 *        &lt;c:if test="${param.error != null}"&gt;
	 *            &lt;div&gt;
	 *                Failed to login.
	 *                &lt;c:if test="${SPRING_SECURITY_LAST_EXCEPTION != null}"&gt;
	 *                  Reason: &lt;c:out value="${SPRING_SECURITY_LAST_EXCEPTION.message}" /&gt;
	 *                &lt;/c:if&gt;
	 *            &lt;/div&gt;
	 *        &lt;/c:if&gt;
	 *        &lt;!-- the configured LogoutConfigurer#logoutSuccessUrl is /login?logout and contains the query param logout --&gt;
	 *        &lt;c:if test="${param.logout != null}"&gt;
	 *            &lt;div&gt;
	 *                You have been logged out.
	 *            &lt;/div&gt;
	 *        &lt;/c:if&gt;
	 *        &lt;p&gt;
	 *        &lt;label for="username"&gt;Username&lt;/label&gt;
	 *        &lt;input type="text" id="username" name="username"/&gt;
	 *        &lt;/p&gt;
	 *        &lt;p&gt;
	 *        &lt;label for="password"&gt;Password&lt;/label&gt;
	 *        &lt;input type="password" id="password" name="password"/&gt;
	 *        &lt;/p&gt;
	 *        &lt;!-- if using RememberMeConfigurer make sure remember-me matches RememberMeConfigurer#rememberMeParameter --&gt;
	 *        &lt;p&gt;
	 *        &lt;label for="remember-me"&gt;Remember Me?&lt;/label&gt;
	 *        &lt;input type="checkbox" id="remember-me" name="remember-me"/&gt;
	 *        &lt;/p&gt;
	 *        &lt;div&gt;
	 *            &lt;button type="submit" class="btn"&gt;Log in&lt;/button&gt;
	 *        &lt;/div&gt;
	 *    &lt;/fieldset&gt;
	 * &lt;/form&gt;
	 * </pre>
	 *
	 * <h2>Impact on other defaults</h2>
	 * <p>
	 * Updating this value, also impacts a number of other default values. For example,
	 * the following are the default values when only formLogin() was specified.
	 *
	 * <ul>
	 * <li>/login GET - the login form</li>
	 * <li>/login POST - process the credentials and if valid authenticate the user</li>
	 * <li>/login?error GET - redirect here for failed authentication attempts</li>
	 * <li>/login?logout GET - redirect here after successfully logging out</li>
	 * </ul>
	 * <p>
	 * If "/authenticate" was passed to this method it update the defaults as shown below:
	 *
	 * <ul>
	 * <li>/authenticate GET - the login form</li>
	 * <li>/authenticate POST - process the credentials and if valid authenticate the user
	 * </li>
	 * <li>/authenticate?error GET - redirect here for failed authentication attempts</li>
	 * <li>/authenticate?logout GET - redirect here after successfully logging out</li>
	 * </ul>
	 *
	 * @param loginPage the login page to redirect to if authentication is required (i.e.
	 *                  "/login")
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	@Override
	public FormLoginConfigurer<H> loginPage(String loginPage) {
		return super.loginPage(loginPage);
	}

	/**
	 * 设置Http请求的参数，默认为"username"
	 * 用来自定义用户参数名，默认 username 。
	 * The HTTP parameter to look for the username when performing authentication. Default
	 * is "username".
	 *
	 * @param usernameParameter the HTTP parameter to look for the username when
	 *                          performing authentication
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> usernameParameter(String usernameParameter) {
		getAuthenticationFilter().setUsernameParameter(usernameParameter);
		return this;
	}

	/**
	 * 设置Http请求参数的密码，默认为"password"
	 * 用来自定义用户密码名，默认 password
	 * The HTTP parameter to look for the password when performing authentication. Default
	 * is "password".
	 *
	 * @param passwordParameter the HTTP parameter to look for the password when
	 *                          performing authentication
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> passwordParameter(String passwordParameter) {
		getAuthenticationFilter().setPasswordParameter(passwordParameter);
		return this;
	}

	/**
	 * 登录失败会转发到此， 一般前后分离用到它。 可定义一个 Controller （控制器）来处理返回值,但是要注意 RequestMethod。
	 * Forward Authentication Failure Handler
	 *
	 * @param forwardUrl the target URL in case of failure
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> failureForwardUrl(String forwardUrl) {
		failureHandler(new ForwardAuthenticationFailureHandler(forwardUrl));
		return this;
	}

	/**
	 * 转发身份验证成功处理程序
	 * 效果等同于上面 defaultSuccessUrl 的 alwaysUse 为 true 但是要注意 RequestMethod。
	 * Forward Authentication Success Handler
	 *
	 * @param forwardUrl the target URL in case of success
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public FormLoginConfigurer<H> successForwardUrl(String forwardUrl) {
		successHandler(new ForwardAuthenticationSuccessHandler(forwardUrl));
		return this;
	}

	/**
	 * 初始化操作
	 *
	 * @param http
	 * @throws Exception
	 */
	@Override
	public void init(H http) throws Exception {
		super.init(http);
		initDefaultLoginFilter(http);
	}

	/*根据给定的登录处理url创建表单登录请求匹配器
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.config.annotation.web.configurers.
	 * AbstractAuthenticationFilterConfigurer
	 * #createLoginProcessingUrlMatcher(java.lang.String)
	 */
	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl, "POST");
	}

	/**
	 * Gets the HTTP parameter that is used to submit the username.
	 *
	 * @return the HTTP parameter that is used to submit the username
	 */
	private String getUsernameParameter() {
		return getAuthenticationFilter().getUsernameParameter();
	}

	/**
	 * Gets the HTTP parameter that is used to submit the password.
	 *
	 * @return the HTTP parameter that is used to submit the password
	 */
	private String getPasswordParameter() {
		return getAuthenticationFilter().getPasswordParameter();
	}

	/**
	 * If available, initializes the {@link DefaultLoginPageGeneratingFilter} shared
	 * object.
	 *
	 * @param http the {@link HttpSecurityBuilder} to use
	 */
	private void initDefaultLoginFilter(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null && !isCustomLoginPage()) {
			loginPageGeneratingFilter.setFormLoginEnabled(true);
			loginPageGeneratingFilter.setUsernameParameter(getUsernameParameter());
			loginPageGeneratingFilter.setPasswordParameter(getPasswordParameter());
			loginPageGeneratingFilter.setLoginPageUrl(getLoginPage());
			loginPageGeneratingFilter.setFailureUrl(getFailureUrl());
			loginPageGeneratingFilter.setAuthenticationUrl(getLoginProcessingUrl());
		}
	}
}
