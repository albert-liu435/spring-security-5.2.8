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
package org.springframework.security.web;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * https://andyboke.blog.csdn.net/article/details/90256168
 * 定义过滤器链来处理请求
 * <p>
 * SecurityFilterChain，字面意思"安全过滤器链",是Spring Security Web对匹配特定HTTP请求的一组安全过滤器的抽象建模。这样的一个对象在配置阶段用于配置FilterChainProxy,而FilterChainProxy在请求到达时会使用所持有的某个SecurityFilterChain判断该请求是否匹配该SecurityFilterChain,如果匹配的话，该SecurityFilterChain会被应用到该请求上。
 * <p>
 * FilterChainProxy是Spring Security Web添加到Servlet容器用于安全控制的一个Filter，换句话讲，从Servlet容器的角度来看，Spring Security Web所提供的安全逻辑就是一个Filter,实现类为FilterChainProxy。而实际上在FilterChainProxy内部，它组合了多个SecurityFilterChain,而每个SecurityFilterChain又组合了一组Filter,这组Filter也实现了Servlet Filter接口，但是它们对于整个Servlet容器来讲是不可见的。在本文中，你可以简单地将FilterChainProxy理解成多个SecurityFilterChain的一个封装。
 * <p>
 * SecurityFilterChain接口其实就定义了两个方法 :
 * <p>
 * 判断某个请求是否匹配该安全过滤器链 – boolean matches(HttpServletRequest request)
 * 获取该安全过滤器链所对应的安全过滤器 – List<Filter> getFilters()
 * 这组安全过滤器会最终被应用到所匹配的请求上
 * <p>
 * 从SecurityFilterChain接口定义看不到一个SecurityFilterChain对象是如何提供请求匹配的标准的。Spring Security Web对SecurityFilterChain提供了缺省的标准实现DefaultSecurityFilterChain，从DefaultSecurityFilterChain的实现，你能全面地看到Spring Security Web在该功能点上的解决方案。
 * <p>
 * 一个DefaultSecurityFilterChain对象定义时需要提供以下信息 ：
 * <p>
 * 一个用于匹配特定请求的请求匹配器requestMatcher;
 * 针对所匹配的请求要应用的一组过滤器。
 * SecurityFilterChain/DefaultSecurityFilterChain代码都不算复杂，但是做到了向使用者Servlet容器屏蔽细节，这也算是软件工程中"关注点分离"这一概念的良好应用。
 * Defines a filter chain which is capable of being matched against an
 * {@code HttpServletRequest}. in order to decide whether it applies to that request.
 * <p>
 * Used to configure a {@code FilterChainProxy}.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public interface SecurityFilterChain {

	/**
	 * 判断某个请求是否匹配该安全过滤器链
	 *
	 * @param request
	 * @return
	 */
	boolean matches(HttpServletRequest request);

	/**
	 * 获取该安全过滤器链所对应的安全过滤器
	 *
	 * @return
	 */
	List<Filter> getFilters();
}
