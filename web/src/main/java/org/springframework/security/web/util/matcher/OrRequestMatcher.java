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
package org.springframework.security.web.util.matcher;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * {@link RequestMatcher}，如果传入的{@link RequestMatcher}实例匹配，则返回true。
 * {@link RequestMatcher} that will return true if any of the passed in
 * {@link RequestMatcher} instances match.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class OrRequestMatcher implements RequestMatcher {
	private final Log logger = LogFactory.getLog(getClass());
	private final List<RequestMatcher> requestMatchers;

	/**
	 * 创建一个实例
	 * Creates a new instance
	 *
	 * @param requestMatchers the {@link RequestMatcher} instances to try
	 */
	public OrRequestMatcher(List<RequestMatcher> requestMatchers) {
		Assert.notEmpty(requestMatchers, "requestMatchers must contain a value");
		if (requestMatchers.contains(null)) {
			throw new IllegalArgumentException(
					"requestMatchers cannot contain null values");
		}
		this.requestMatchers = requestMatchers;
	}

	/**
	 * Creates a new instance
	 *
	 * @param requestMatchers the {@link RequestMatcher} instances to try
	 */
	public OrRequestMatcher(RequestMatcher... requestMatchers) {
		this(Arrays.asList(requestMatchers));
	}

	/**
	 * 判断该请求是否匹配
	 *
	 * @param request the request to check for a match
	 * @return
	 */
	public boolean matches(HttpServletRequest request) {
		//如logout请求
//		new AntPathRequestMatcher(this.logoutUrl, "GET"),
//				new AntPathRequestMatcher(this.logoutUrl, "POST"),
//				new AntPathRequestMatcher(this.logoutUrl, "PUT"),
//				new AntPathRequestMatcher(this.logoutUrl, "DELETE")
		for (RequestMatcher matcher : requestMatchers) {
			if (logger.isDebugEnabled()) {
				logger.debug("Trying to match using " + matcher);
			}
			if (matcher.matches(request)) {
				logger.debug("matched");
				return true;
			}
		}
		logger.debug("No matches found");
		return false;
	}

	@Override
	public String toString() {
		return "OrRequestMatcher [requestMatchers=" + requestMatchers + "]";
	}
}
