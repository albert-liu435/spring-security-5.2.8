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

package org.springframework.security.web.access.intercept;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;

/**
 * https://blog.csdn.net/liuminglei1987/article/details/107662200
 * <p>
 * 承担着非常重要的作用。如获取当前 request 对应的权限配置，调用访问控制器进行鉴权操作等，都是核心功能。
 * <p>
 * <p>
 * https://felord.cn/spring-security-dynamic-rbac-b.html
 * <p>
 * https://andyboke.blog.csdn.net/article/details/85168419
 * <p>
 * 此过滤器FilterSecurityInterceptor是一个请求处理过程中安全机制过滤器链中最后一个filter,它执行真正的HTTP资源安全控制。
 * <p>
 * 具体代码实现上，FilterSecurityInterceptor主要是将请求上下文包装成一个FilterInvocation然后对它进行操作。FilterSecurityInterceptor仅仅包含调用FilterInvocation的主要流程。具体的安全控制细节，
 * 在其基类AbstractSecurityInterceptor中实现。
 * <p>
 * <p>
 * 这个过滤器决定了访问特定路径应该具备的权限，访问的用户的角色，权限是什么？访问的路径需要什么样的角色和权限？这些判断和处理都是由该类进行的。
 * <p>
 * 想想整个认证安全控制流程还缺了什么？我们已经有了认证，有了请求的封装，有了 Session 的关联… 还缺一个：由什么控制哪些资源是受限的，这些受限的资源需要什么权限，需要什么角色… 这一切和访问控制相关的操作，
 * 都是由 FilterSecurityInterceptor 完成的。
 * <p>
 * <p>
 * FilterSecurityInterceptor 从 SecurityContextHolder 中获取 Authentication 对象，然后比对用户拥有的权限和资源所需的权限。前者可以通过 Authentication 对象直接获得，而后者则需要引入我们之前一直未提到过的两个类：
 * SecurityMetadataSource，AccessDecisionManager。理解清楚决策管理器的整个创建流程和 SecurityMetadataSource 的作用需要花很大一笔功夫，这里，暂时只介绍其大概的作用。
 * <p>
 * Performs security handling of HTTP resources via a filter implementation.
 * <p>
 * The <code>SecurityMetadataSource</code> required by this security interceptor is of
 * type {@link FilterInvocationSecurityMetadataSource}.
 * <p>
 * Refer to {@link AbstractSecurityInterceptor} for details on the workflow.
 * </p>
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class FilterSecurityInterceptor extends AbstractSecurityInterceptor implements
		Filter {
	// ~ Static fields/initializers
	// =====================================================================================

	private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

	// ~ Instance fields
	// ================================================================================================

	private FilterInvocationSecurityMetadataSource securityMetadataSource;
	//其实，很简单。比如用户发起某个访问请求，首先经过默认的 FilterSecurityInterceptor，经过权限检查，需要身份认证权限，此时已经登录，权限认证通过；再交给自定义 FilterSecurityInterceptor 处理，但是，由于默认的 observeOncePerRequest 属性为 true，
// 在默认的 FilterSecurityInterceptor 处理后，已经对此请求添加了已经处理的标识，所以自定义 FilterSecurityInterceptor 就直接跳过，不再处理。
	private boolean observeOncePerRequest = true;

	// ~ Methods
	// ========================================================================================================

	/**
	 * Not used (we rely on IoC container lifecycle services instead)
	 *
	 * @param arg0 ignored
	 */
	public void init(FilterConfig arg0) {
	}

	/**
	 * Not used (we rely on IoC container lifecycle services instead)
	 */
	public void destroy() {
	}

	/**
	 * Method that is actually called by the filter chain. Simply delegates to the
	 * {@link #invoke(FilterInvocation)} method.
	 *
	 * @param request  the servlet request
	 * @param response the servlet response
	 * @param chain    the filter chain
	 * @throws IOException      if the filter chain fails
	 * @throws ServletException if the filter chain fails
	 */
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		// 封装请求上下文为一个FilterInvocation,然后调用该FilterInvocation执行安全认证
		FilterInvocation fi = new FilterInvocation(request, response, chain);
		invoke(fi);
	}

	public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

	public SecurityMetadataSource obtainSecurityMetadataSource() {
		return this.securityMetadataSource;
	}

	public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource newSource) {
		this.securityMetadataSource = newSource;
	}

	public Class<?> getSecureObjectClass() {
		return FilterInvocation.class;
	}

	/**
	 * 执行该方法
	 *
	 * @param fi
	 * @throws IOException
	 * @throws ServletException
	 */
	public void invoke(FilterInvocation fi) throws IOException, ServletException {
		if ((fi.getRequest() != null)
				&& (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
				&& observeOncePerRequest) {
			// filter already applied to this request and user wants us to observe
			// once-per-request handling, so don't re-do security checking
			// 如果被指定为在整个请求处理过程中只能执行最多一次 ,并且监测到已经执行过,
			// 则直接放行，继续 filter chain 的执行
			fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
		} else {
			// first time this request being called, so perform security checking
			// 如果被指定为在整个请求处理过程中只能执行最多一次 ,并且监测到尚未执行,
			// 则设置已经执行标志，随后执行职责逻辑
			if (fi.getRequest() != null && observeOncePerRequest) {
				//设置为已经执行
				fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
			}
			// 这里是该过滤器进行安全检查的职责逻辑,具体实现在基类AbstractSecurityInterceptor
			// 主要是进行必要的认证和授权检查，如果遇到相关异常则抛出异常，之后的过滤器链
			// 调用不会继续进行
			//获取当前 request 对应的权限配置
			InterceptorStatusToken token = super.beforeInvocation(fi);

			try {
				// 如果上面通过安全检查，这里继续过滤器的执行
				fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
			} finally {
				//待请求完成后会在 finallyInvocation() 中将原来的 SecurityContext 重新设置给SecurityContextHolder。
				super.finallyInvocation(token);
			}
//// 正常请求结束，最后也会执行（afterInvocation 内部会调用finallyInvocation ）
			super.afterInvocation(token, null);
		}
	}

	/**
	 * // 指定是否在整个请求处理过程中该过滤器只被执行一次，缺省是 true。
	 * // 也存在在整个请求处理过程中该过滤器需要执行多次的情况，比如JSP foward/include
	 * // 等情况。
	 * Indicates whether once-per-request handling will be observed. By default this is
	 * <code>true</code>, meaning the <code>FilterSecurityInterceptor</code> will only
	 * execute once-per-request. Sometimes users may wish it to execute more than once per
	 * request, such as when JSP forwards are being used and filter security is desired on
	 * each included fragment of the HTTP request.
	 *
	 * @return <code>true</code> (the default) if once-per-request is honoured, otherwise
	 * <code>false</code> if <code>FilterSecurityInterceptor</code> will enforce
	 * authorizations for each and every fragment of the HTTP request.
	 */
	public boolean isObserveOncePerRequest() {
		return observeOncePerRequest;
	}

	public void setObserveOncePerRequest(boolean observeOncePerRequest) {
		this.observeOncePerRequest = observeOncePerRequest;
	}
}
