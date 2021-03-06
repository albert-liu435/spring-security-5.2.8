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

package org.springframework.security.web;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.UrlUtils;

/**
 * https://blog.csdn.net/you18131371836/article/details/71126787
 * <p>
 * https://zhuanlan.zhihu.com/p/86662663
 * <p>
 * 保存与HTTP过滤关联的对象。
 * <p>
 * 通过Spring Security 封装，可以安全的拿到HttpServletRequest 和 HttpServletResponse对象
 * <p>
 * 项目中用到了 getRequestUrl() 获取请求url
 * <p>
 * 这个类的作用本身很简单，就是把doFilter传进来的request,response和FilterChain对象保存起来，供FilterSecurityInterceptor的处理代码调用。
 * <p>
 * 在我来写FilterSecurityInterceptor类的代码时，FilterInvocation类的出生机率会很小，一般都会直接把doFilter的参数要么保存在FilterSecurityInterceptor类的相关属性里，
 * 要么就是直接传进来用，并且不断地在各个方法中传递这些参数。由此可见springSecurity的作者这个小小的设计使得代码的可阅读性和藕合性大大降低，因为FilterInvocation类替代了这些参数在FilterSecurityInterceptor类中各处游动，，这样通过该类屏蔽了web filter过滤器环境。
 * <p>
 * Holds objects associated with a HTTP filter.
 * <p>
 * 保证请求和响应是HttpServletRequest和HttpServletResponse的实例
 * 这样安全系统类就可以获得对过滤器环境的访问，以及请求和响应。
 * Guarantees the request and response are instances of <code>HttpServletRequest</code>
 * and <code>HttpServletResponse</code>, and that there are no <code>null</code> objects.
 * <p>
 * Required so that security system classes can obtain access to the filter environment,
 * as well as the request and response.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @author Luke Taylor
 * @author Rob Winch
 */
public class FilterInvocation {
	// ~ Static fields
	// ==================================================================================================
	static final FilterChain DUMMY_CHAIN = (req, res) -> {
		throw new UnsupportedOperationException("Dummy filter chain");
	};

	// ~ Instance fields
	// ================================================================================================

	private FilterChain chain;
	private HttpServletRequest request;
	private HttpServletResponse response;

	// ~ Constructors
	// ===================================================================================================

	public FilterInvocation(ServletRequest request, ServletResponse response,
			FilterChain chain) {
		if ((request == null) || (response == null) || (chain == null)) {
			throw new IllegalArgumentException("Cannot pass null values to constructor");
		}

		this.request = (HttpServletRequest) request;
		this.response = (HttpServletResponse) response;
		this.chain = chain;
	}

	public FilterInvocation(String servletPath, String method) {
		this(null, servletPath, method);
	}

	public FilterInvocation(String contextPath, String servletPath, String method) {
		this(contextPath, servletPath, null, null, method);
	}

	public FilterInvocation(String contextPath, String servletPath, String pathInfo,
			String query, String method) {
		DummyRequest request = new DummyRequest();
		if (contextPath == null) {
			contextPath = "/cp";
		}
		request.setContextPath(contextPath);
		request.setServletPath(servletPath);
		request.setRequestURI(
				contextPath + servletPath + (pathInfo == null ? "" : pathInfo));
		request.setPathInfo(pathInfo);
		request.setQueryString(query);
		request.setMethod(method);
		this.request = request;
	}

	// ~ Methods
	// ========================================================================================================

	public FilterChain getChain() {
		return this.chain;
	}

	/**
	 * Indicates the URL that the user agent used for this request.
	 * <p>
	 * The returned URL does <b>not</b> reflect the port number determined from a
	 * {@link org.springframework.security.web.PortResolver}.
	 *
	 * @return the full URL of this request
	 */
	public String getFullRequestUrl() {
		return UrlUtils.buildFullRequestUrl(this.request);
	}

	/**
	 * 获取当前请求
	 * @return
	 */
	public HttpServletRequest getHttpRequest() {
		return this.request;
	}

	public HttpServletResponse getHttpResponse() {
		return this.response;
	}

	/**
	 * Obtains the web application-specific fragment of the URL.
	 *
	 * @return the URL, excluding any server name, context path or servlet path
	 */
	public String getRequestUrl() {
		return UrlUtils.buildRequestUrl(this.request);
	}

	/**
	 * 获取当前请求
	 *
	 * @return
	 */
	public HttpServletRequest getRequest() {
		return getHttpRequest();
	}

	public HttpServletResponse getResponse() {
		return getHttpResponse();
	}

	@Override
	public String toString() {
		return "FilterInvocation: URL: " + getRequestUrl();
	}
}

class DummyRequest extends HttpServletRequestWrapper {
	private static final HttpServletRequest UNSUPPORTED_REQUEST = (HttpServletRequest) Proxy
			.newProxyInstance(DummyRequest.class.getClassLoader(),
					new Class[]{HttpServletRequest.class},
					new UnsupportedOperationExceptionInvocationHandler());

	private String requestURI;
	private String contextPath = "";
	private String servletPath;
	private String pathInfo;
	private String queryString;
	private String method;

	DummyRequest() {
		super(UNSUPPORTED_REQUEST);
	}

	public String getCharacterEncoding() {
		return "UTF-8";
	}

	public Object getAttribute(String attributeName) {
		return null;
	}

	public void setRequestURI(String requestURI) {
		this.requestURI = requestURI;
	}

	public void setPathInfo(String pathInfo) {
		this.pathInfo = pathInfo;
	}

	@Override
	public String getRequestURI() {
		return this.requestURI;
	}

	public void setContextPath(String contextPath) {
		this.contextPath = contextPath;
	}

	@Override
	public String getContextPath() {
		return this.contextPath;
	}

	public void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	@Override
	public String getServletPath() {
		return this.servletPath;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	@Override
	public String getMethod() {
		return this.method;
	}

	@Override
	public String getPathInfo() {
		return this.pathInfo;
	}

	@Override
	public String getQueryString() {
		return this.queryString;
	}

	public void setQueryString(String queryString) {
		this.queryString = queryString;
	}

	@Override
	public String getServerName() {
		return null;
	}
}

final class UnsupportedOperationExceptionInvocationHandler implements InvocationHandler {
	public Object invoke(Object proxy, Method method, Object[] args) {
		throw new UnsupportedOperationException(method + " is not supported");
	}
}
