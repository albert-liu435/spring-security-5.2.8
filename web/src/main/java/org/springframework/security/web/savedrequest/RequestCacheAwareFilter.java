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
package org.springframework.security.web.savedrequest;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * https://andyboke.blog.csdn.net/article/details/84862635
 * <p>
 * Spring Security Web对请求提供了缓存机制，如果某个请求被缓存，它的提取和使用是交给RequestCacheAwareFilter完成的。
 * <p>
 * 系统在启动时，Spring Security Web会首先尝试从容器中获取一个RequestCache bean,获取失败的话，会构建一个缺省的RequestCache对象，然后实例化该过滤器 。
 * <p>
 * 如果容器中不存在RequestCache bean,Spring Security Web所使用的缺省RequestCache是一个HttpSessionRequestCache,它会将请求保存在http session中，而且不是所有的请求都会被缓存，而是只有符合以下条件的请求才被缓存 ：
 * <p>
 * 必须是 GET /**
 * 并且不能是 favicon.*
 * 并且不能是 application.json
 * 并且不能是 XMLHttpRequest(也就是一般意义上的 ajax 请求)
 * Responsible for reconstituting the saved request if one is cached and it matches the
 * current request.
 * <p>
 * It will call
 * {@link RequestCache#getMatchingRequest(HttpServletRequest, HttpServletResponse)
 * getMatchingRequest} on the configured <tt>RequestCache</tt>. If the method returns a
 * value (a wrapper of the saved request), it will pass this to the filter chain's
 * <tt>doFilter</tt> method. If null is returned by the cache, the original request is
 * used and the filter has no effect.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class RequestCacheAwareFilter extends GenericFilterBean {

	private RequestCache requestCache;

	// 使用http session 作为请求缓存的构造函数
	public RequestCacheAwareFilter() {
		this(new HttpSessionRequestCache());
	}

	// 外部指定请求缓存对象的构造函数
	public RequestCacheAwareFilter(RequestCache requestCache) {
		Assert.notNull(requestCache, "requestCache cannot be null");
		this.requestCache = requestCache;
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		// 尝试从请求缓存中获取跟当前请求匹配的被缓存的请求
		HttpServletRequest wrappedSavedRequest = requestCache.getMatchingRequest(
				(HttpServletRequest) request, (HttpServletResponse) response);
// 如果从缓存中获取的请求不为空，使用它继续filter chain的执行，
		// 否则使用参数request继续filter chain的执
		chain.doFilter(wrappedSavedRequest == null ? request : wrappedSavedRequest,
				response);
	}

}
