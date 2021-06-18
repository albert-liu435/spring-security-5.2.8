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
package org.springframework.security.web.authentication.ui;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * https://andyboke.blog.csdn.net/article/details/84748206
 * 当开发人员在安全配置中没有配置登录页面时，Spring Security Web会自动构造一个登录页面给用户。完成这一任务是通过一个过滤器来完成的，该过滤器就是DefaultLoginPageGeneratingFilter。
 * <p>
 * 该过滤器支持两种登录情景:
 * <p>
 * 用户名/密码表单登录
 * OpenID表单登录
 * 无论以上哪种登录情景，该过滤器都会使用以下信息用于构建登录HTML页面 :
 * <p>
 * 当前请求是否为登录页面请求的匹配器定义–由配置明确指定或者使用缺省值 /login
 * 当前请求是否跳转自登录错误处理以及相应异常信息 – 缺省对应url : /login?error
 * 当前请求是否跳转自退出登录成功处理 – 缺省对应url : /login?logout
 * 配置指定使用用户名/密码表单登录还是OpenID表单登录
 * 表单构建信息
 * csrf token信息
 * 针对用户名/密码表单登录的表单构建信息
 * 登录表单提交处理地址
 * 用户名表单字段名称
 * 密码表单字段名称
 * RememberMe 表单字段名称
 * 针对OpenID表单登录的表单构建信息
 * 登录表单提交处理地址
 * OpenID表单字段名称
 * RememberMe 表单字段名称
 * 该过滤器被请求到达时会首先看是不是自己关注的请求，如果是，则会根据相应信息构建一个登录页面HTML直接写回浏览器端，对该请求的处理也到此结束，不再继续调用filter chain中的其他逻辑。
 * <p>
 * <p>
 * 内部使用的一个过滤器，当用户没有指定一个登录页面时，安全配置逻辑自动插入这样一个过滤器用于
 * 自动生成一个登录页面。
 * For internal use with namespace configuration in the case where a user doesn't
 * configure a login page. The configuration code will insert this filter in the chain
 * instead.
 * <p>
 * Will only work if a redirect is used to the login page.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class DefaultLoginPageGeneratingFilter extends GenericFilterBean {
	public static final String DEFAULT_LOGIN_PAGE_URL = "/login";
	public static final String ERROR_PARAMETER_NAME = "error";
	private String loginPageUrl;
	private String logoutSuccessUrl;
	private String failureUrl;
	private boolean formLoginEnabled;
	private boolean openIdEnabled;
	private boolean oauth2LoginEnabled;
	private boolean saml2LoginEnabled;
	// 用于构造用户名/密码表单登录页面的参数
	// 表单提交时的认证处理地址
	private String authenticationUrl;
	//	 用户名表单字段的名称
	private String usernameParameter;
	//	 密码表单字段的名称
	private String passwordParameter;
	//	 rememberMe表单字段的名称
	private String rememberMeParameter;
	// 用于构造openID表单登录页面的参数
	//提交时的认证处理地址
	private String openIDauthenticationUrl;
	//	 用户名表单字段的名称
	private String openIDusernameParameter;
	private String openIDrememberMeParameter;
	private Map<String, String> oauth2AuthenticationUrlToClientName;
	private Map<String, String> saml2AuthenticationUrlToProviderName;
	//设置用于解析隐藏输入映射的函数，其中键是输入的名称，值是输入的值。通常，这用于解析CSRF令牌。
	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = request -> Collections
			.emptyMap();


	public DefaultLoginPageGeneratingFilter() {
	}

	public DefaultLoginPageGeneratingFilter(AbstractAuthenticationProcessingFilter filter) {
		if (filter instanceof UsernamePasswordAuthenticationFilter) {
			init((UsernamePasswordAuthenticationFilter) filter, null);
		} else {
			init(null, filter);
		}
	}

	public DefaultLoginPageGeneratingFilter(
			UsernamePasswordAuthenticationFilter authFilter,
			AbstractAuthenticationProcessingFilter openIDFilter) {
		init(authFilter, openIDFilter);
	}

	// 支持两种登录方式:用户名/密码表单登录,openID登录，根据提供的filter参数的类型
	// 判断使用了哪种登录方式
	private void init(UsernamePasswordAuthenticationFilter authFilter,
			AbstractAuthenticationProcessingFilter openIDFilter) {
		// 登录页面，缺省为 /logoin
		this.loginPageUrl = DEFAULT_LOGIN_PAGE_URL;
		// 默认的退出登录成功页面 /login?logout
		this.logoutSuccessUrl = DEFAULT_LOGIN_PAGE_URL + "?logout";
		// 登录出错页面, 缺省为 /login?error
		this.failureUrl = DEFAULT_LOGIN_PAGE_URL + "?" + ERROR_PARAMETER_NAME;
		if (authFilter != null) {
			formLoginEnabled = true;
			usernameParameter = authFilter.getUsernameParameter();
			passwordParameter = authFilter.getPasswordParameter();

			if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
				rememberMeParameter = ((AbstractRememberMeServices) authFilter
						.getRememberMeServices()).getParameter();
			}
		}

		if (openIDFilter != null) {
			openIdEnabled = true;
			openIDusernameParameter = "openid_identifier";

			if (openIDFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
				openIDrememberMeParameter = ((AbstractRememberMeServices) openIDFilter
						.getRememberMeServices()).getParameter();
			}
		}
	}

	/**
	 * 设置用于解析隐藏输入映射的函数，其中键是输入的名称，值是输入的值。通常，这用于解析CSRF令牌。
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input. Typically this is used
	 * to resolve the CSRF token.
	 *
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(
			Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	public boolean isEnabled() {
		return formLoginEnabled || openIdEnabled || oauth2LoginEnabled || this.saml2LoginEnabled;
	}

	public void setLogoutSuccessUrl(String logoutSuccessUrl) {
		this.logoutSuccessUrl = logoutSuccessUrl;
	}

	public String getLoginPageUrl() {
		return loginPageUrl;
	}

	public void setLoginPageUrl(String loginPageUrl) {
		this.loginPageUrl = loginPageUrl;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	public void setFormLoginEnabled(boolean formLoginEnabled) {
		this.formLoginEnabled = formLoginEnabled;
	}

	public void setOpenIdEnabled(boolean openIdEnabled) {
		this.openIdEnabled = openIdEnabled;
	}

	public void setOauth2LoginEnabled(boolean oauth2LoginEnabled) {
		this.oauth2LoginEnabled = oauth2LoginEnabled;
	}

	public void setSaml2LoginEnabled(boolean saml2LoginEnabled) {
		this.saml2LoginEnabled = saml2LoginEnabled;
	}

	public void setAuthenticationUrl(String authenticationUrl) {
		this.authenticationUrl = authenticationUrl;
	}

	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}

	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

	public void setRememberMeParameter(String rememberMeParameter) {
		this.rememberMeParameter = rememberMeParameter;
		this.openIDrememberMeParameter = rememberMeParameter;
	}

	public void setOpenIDauthenticationUrl(String openIDauthenticationUrl) {
		this.openIDauthenticationUrl = openIDauthenticationUrl;
	}

	public void setOpenIDusernameParameter(String openIDusernameParameter) {
		this.openIDusernameParameter = openIDusernameParameter;
	}

	public void setOauth2AuthenticationUrlToClientName(Map<String, String> oauth2AuthenticationUrlToClientName) {
		this.oauth2AuthenticationUrlToClientName = oauth2AuthenticationUrlToClientName;
	}

	public void setSaml2AuthenticationUrlToProviderName(Map<String, String> saml2AuthenticationUrlToProviderName) {
		this.saml2AuthenticationUrlToProviderName = saml2AuthenticationUrlToProviderName;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		// 检测是否登录错误页面请求
		boolean loginError = isErrorPage(request);
		// 检测是否退出登录成功页面请求
		boolean logoutSuccess = isLogoutSuccess(request);
		// 检测是否登录页面请求
		if (isLoginUrlRequest(request) || loginError || logoutSuccess) {
			//生成登录页面
			// 如果是上面三种任何一种情况，则自动生成一个登录HTML页面写回响应，
			// 该方法返回，当前请求的处理结束。

			// 生成登录页面的HTML内容
			String loginPageHtml = generateLoginPageHtml(request, loginError,
					logoutSuccess);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
			// 将登录页面HTML内容写回浏览器
			response.getWriter().write(loginPageHtml);
			// 当前请求的处理已经结果，方法返回，不再继续filter chain的调用
			return;
		}
		// 如果不是需要渲染一个登录页面的其他情形，继续filter chain的调用
		chain.doFilter(request, response);
	}

	/**
	 * // 生成登录页面
	 * // 会根据当前是用户名/密码表单登录请求还是openID表单登录请求生成不同的HTML
	 *
	 * @param request
	 * @param loginError
	 * @param logoutSuccess
	 * @return
	 */
	private String generateLoginPageHtml(HttpServletRequest request, boolean loginError,
			boolean logoutSuccess) {
		//
		String errorMsg = "Invalid credentials";

		if (loginError) {
			// 如果是登录错误，则从session中获取登录错误异常信息，该错误信息会组织到
			// 回写给浏览器端的HTML页面中
			HttpSession session = request.getSession(false);

			if (session != null) {
				AuthenticationException ex = (AuthenticationException) session
						.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
				errorMsg = ex != null ? ex.getMessage() : "Invalid credentials";
			}
		}

		StringBuilder sb = new StringBuilder();

		sb.append("<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n"
				+ "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "     <div class=\"container\">\n");

		String contextPath = request.getContextPath();
		if (this.formLoginEnabled) {
			sb.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath + this.authenticationUrl + "\">\n"
					+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
					+ createError(loginError, errorMsg)
					+ createLogoutSuccess(logoutSuccess)
					+ "        <p>\n"
					+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
					+ "          <input type=\"text\" id=\"username\" name=\"" + this.usernameParameter + "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
					+ "        </p>\n"
					+ "        <p>\n"
					+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
					+ "          <input type=\"password\" id=\"password\" name=\"" + this.passwordParameter + "\" class=\"form-control\" placeholder=\"Password\" required>\n"
					+ "        </p>\n"
					+ createRememberMe(this.rememberMeParameter)
					+ renderHiddenInputs(request)
					+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
					+ "      </form>\n");
		}

		if (openIdEnabled) {
			sb.append("      <form name=\"oidf\" class=\"form-signin\" method=\"post\" action=\"" + contextPath + this.openIDauthenticationUrl + "\">\n"
					+ "        <h2 class=\"form-signin-heading\">Login with OpenID Identity</h2>\n"
					+ createError(loginError, errorMsg)
					+ createLogoutSuccess(logoutSuccess)
					+ "        <p>\n"
					+ "          <label for=\"username\" class=\"sr-only\">Identity</label>\n"
					+ "          <input type=\"text\" id=\"username\" name=\"" + this.openIDusernameParameter + "\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
					+ "        </p>\n"
					+ createRememberMe(this.openIDrememberMeParameter)
					+ renderHiddenInputs(request)
					+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
					+ "      </form>\n");
		}

		if (oauth2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with OAuth 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> clientAuthenticationUrlToClientName : oauth2AuthenticationUrlToClientName.entrySet()) {
				sb.append(" <tr><td>");
				String url = clientAuthenticationUrlToClientName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String clientName = HtmlUtils.htmlEscape(clientAuthenticationUrlToClientName.getValue());
				sb.append(clientName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}

		if (this.saml2LoginEnabled) {
			sb.append("<h2 class=\"form-signin-heading\">Login with SAML 2.0</h2>");
			sb.append(createError(loginError, errorMsg));
			sb.append(createLogoutSuccess(logoutSuccess));
			sb.append("<table class=\"table table-striped\">\n");
			for (Map.Entry<String, String> relyingPartyUrlToName : saml2AuthenticationUrlToProviderName.entrySet()) {
				sb.append(" <tr><td>");
				String url = relyingPartyUrlToName.getKey();
				sb.append("<a href=\"").append(contextPath).append(url).append("\">");
				String partyName = HtmlUtils.htmlEscape(relyingPartyUrlToName.getValue());
				sb.append(partyName);
				sb.append("</a>");
				sb.append("</td></tr>\n");
			}
			sb.append("</table>\n");
		}
		sb.append("</div>\n");
		sb.append("</body></html>");

		return sb.toString();
	}

	// 如果请求的属性:CsrfToken.class.getName()有值，则渲染一个隐藏的针对csrf token的表单输入框
	// 默认名称是 _csrf
	private String renderHiddenInputs(HttpServletRequest request) {
		StringBuilder sb = new StringBuilder();
		for (Map.Entry<String, String> input : this.resolveHiddenInputs.apply(request).entrySet()) {
			sb.append("<input name=\"").append(input.getKey()).append("\" type=\"hidden\" value=\"").append(input.getValue()).append("\" />\n");
		}
		return sb.toString();
	}

	private String createRememberMe(String paramName) {
		if (paramName == null) {
			return "";
		}
		return "<p><input type='checkbox' name='"
				+ paramName
				+ "'/> Remember me on this computer.</p>\n";
	}

	private boolean isLogoutSuccess(HttpServletRequest request) {
		return logoutSuccessUrl != null && matches(request, logoutSuccessUrl);
	}

	/**
	 * // 检测当前请求是否是一个登录页面请求
	 *
	 * @param request
	 * @return
	 */
	private boolean isLoginUrlRequest(HttpServletRequest request) {
		return matches(request, loginPageUrl);
	}

	// 检测当前请求是否是一个登录错误页面请求
	private boolean isErrorPage(HttpServletRequest request) {
		return matches(request, failureUrl);
	}

	private static String createError(boolean isError, String message) {
		return isError ? "<div class=\"alert alert-danger\" role=\"alert\">" + HtmlUtils.htmlEscape(message) + "</div>" : "";
	}

	private static String createLogoutSuccess(boolean isLogoutSuccess) {
		return isLogoutSuccess ? "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>" : "";
	}

	private boolean matches(HttpServletRequest request, String url) {
		if (!"GET".equals(request.getMethod()) || url == null) {
			// 参数检查:
			// 1. 对登录页面的请求仅仅支持GET方式
			// 2. url 不能为空
			return false;
		}
		// 获取请求uri，注意其中不包含QueryString部分
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		if (request.getQueryString() != null) {
			uri += "?" + request.getQueryString();
		}
		// 比较请求的uri和预期的url是否相同
		if ("".equals(request.getContextPath())) {
			return uri.equals(url);
		}

		return uri.equals(request.getContextPath() + url);
	}
}
