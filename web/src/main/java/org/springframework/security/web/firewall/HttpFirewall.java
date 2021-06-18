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
package org.springframework.security.web.firewall;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * https://andyboke.blog.csdn.net/article/details/90473899
 * HttpFirewall是Spring Web提供的一个接口，抽象建模HTTP防火墙这一概念。相应对象用于拒绝存在潜在风险的请求或者包装它们以控制它们的行为。该接口的实现类对象会被注入到FilterChainProxy,在安全过滤器链被调用之前该防火墙逻辑会被调用。如果响应对象的行为需要被限制，该防火墙也可以对响应进行包装再返回给请求方。
 * <p>
 * HttpFirewall只定义了两个接口方法，分别对请求/响应对象进行包装。这两个方法都在FilterChainProxy对请求调用过滤器链之前被调用。如果HttpFirewall认为请求有风险，会抛出异常RequestRejectedException从而拒绝该请求。而HttpFirewall封装后的响应对象对设置响应头部方法,cookie设置方法(对应头部Set-Cookie),重定向方法(对应头部Location设置)做了安全加强，确保相应值中不包含\r或者\n。
 * <p>
 * HttpFirewall包装后的请求/相应对象分别是:FirewalledRequest和FirewalledResponse。
 * <p>
 * 可用于拒绝潜在危险请求和/或包装请求以控制其行为的接口。
 * <p>
 * 接口，可用于拒绝潜在的危险请求和/或包装它们以控制它们行为学实现被注入到{@code FilterChainProxy}，并在通过过滤器链发送任何请求之前被调用。如果响应行为也应该受到限制，它还可以提供一个响应包装器。
 * Interface which can be used to reject potentially dangerous requests and/or wrap them
 * to control their behaviour.
 * <p>
 * The implementation is injected into the {@code FilterChainProxy} and will be invoked
 * before sending any request through the filter chain. It can also provide a response
 * wrapper if the response behaviour should also be restricted.
 *
 * @author Luke Taylor
 */
public interface HttpFirewall {

	/**
	 * 提供将通过筛选器链传递的请求对象。
	 * Provides the request object which will be passed through the filter chain.
	 *
	 * @throws RequestRejectedException if the request should be rejected immediately
	 */
	FirewalledRequest getFirewalledRequest(HttpServletRequest request)
			throws RequestRejectedException;

	/**
	 * 提供将通过筛选器链的响应。
	 * Provides the response which will be passed through the filter chain.
	 *
	 * @param response the original response
	 * @return either the original response or a replacement/wrapper.
	 */
	HttpServletResponse getFirewalledResponse(HttpServletResponse response);
}
