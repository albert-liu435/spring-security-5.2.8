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

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 该类的主要功能就是通过当前的请求地址，获取该地址需要的用户角色，我们照猫画虎
 * Default implementation of <tt>FilterInvocationDefinitionSource</tt>.
 * <p>
 * Stores an ordered map of {@link RequestMatcher}s to <tt>ConfigAttribute</tt>
 * collections and provides matching of {@code FilterInvocation}s against the items stored
 * in the map.
 * <p>
 * The order of the {@link RequestMatcher}s in the map is very important. The <b>first</b>
 * one which matches the request will be used. Later matchers in the map will not be
 * invoked if a match has already been found. Accordingly, the most specific matchers
 * should be registered first, with the most general matches registered last.
 * <p>
 * The most common method creating an instance is using the Spring Security namespace. For
 * example, the {@code pattern} and {@code access} attributes of the
 * {@code <intercept-url>} elements defined as children of the {@code <http>}
 * element are combined to build the instance used by the
 * {@code FilterSecurityInterceptor}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class DefaultFilterInvocationSecurityMetadataSource implements
		FilterInvocationSecurityMetadataSource {

	protected final Log logger = LogFactory.getLog(getClass());

	private final Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Sets the internal request map from the supplied map. The key elements should be of
	 * type {@link RequestMatcher}, which. The path stored in the key will depend on the
	 * type of the supplied UrlMatcher.
	 *
	 * @param requestMap order-preserving map of request definitions to attribute lists
	 */
	public DefaultFilterInvocationSecurityMetadataSource(
			LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap) {

		this.requestMap = requestMap;
	}

	// ~ Methods
	// ========================================================================================================

	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttributes = new HashSet<>();

		for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap
				.entrySet()) {
			allAttributes.addAll(entry.getValue());
		}

		return allAttributes;
	}

	/**
	 * Collection<ConfigAttribute> getAttributes(Object object) 方法的实现：肯定是获取请求中的 URI 来和 所有的 资源配置中的 Ant Pattern 进行匹配以获取对应的资源配置, 这里需要将资源查询接口查询的资源配置封装为
	 * AntPathRequestMatcher以方便进行 Ant Match 。
	 * 这里需要特别提一下如果你使用 Restful 风格，这里 增删改查 将非常方便你来对资源的管控。参考的实现：
	 *
	 * @param object the object being secured
	 * @return
	 */
	public Collection<ConfigAttribute> getAttributes(Object object) {
		final HttpServletRequest request = ((FilterInvocation) object).getRequest();
		for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap
				.entrySet()) {
			if (entry.getKey().matches(request)) {
				return entry.getValue();
			}
		}
		return null;
	}

	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}
}
