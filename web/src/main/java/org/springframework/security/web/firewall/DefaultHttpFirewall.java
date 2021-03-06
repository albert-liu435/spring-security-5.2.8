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

/**https://andyboke.blog.csdn.net/article/details/90521548
 * DefaultHttpFirewall是Spring Security Web提供的一个HTTP防火墙(对应概念模型接口HttpFirewall)实现。该实现是所谓的缺省实现，但实际上Spring Security Web缺省使用的并不是DefaultHttpFirewall,而是严格模式的StrictHttpFirewall。其原因主要是StrictHttpFirewall对安全限制更严格，但是开发人员也可以设置Spring Security Web使用DefaultHttpFirewall。
 * <p>
 * DefaultHttpFirewall所应用的安全规则比较少，主要有：
 * <p>
 * 如果请求URL不是标准化(normalize)的URL则该请求会被拒绝，以避免安全限制被绕过。
 * <p>
 * 该规则不能被禁用。
 * 仅仅检查servletPath和pathInfo部分，不检查contextPath。
 * 这里标准化的URL必须符合以下条件 :
 * 指定路径中，必须不能包含以下字符串序列之一 :
 * ["//","./","/…/","/."]
 * <p>
 * 如果请求URL（URL编码后)包含了斜杠(%2f或者%2F)则该请求会被拒绝。
 * <p>
 * 通过开关函数setAllowUrlEncodedSlash(boolean) 可以设置是否关闭该规则。缺省使用该规则。
 * <p>
 * 如果请求违反了以上安全规则中的任何一条，DefaultHttpFirewall会通过抛出异常RequestRejectedException拒绝该请求。
 * <p>
 * User's should consider using {@link StrictHttpFirewall} because rather than trying to
 * sanitize a malicious URL it rejects the malicious URL providing better security
 * guarantees.
 * <p>
 * Default implementation which wraps requests in order to provide consistent
 * values of the {@code servletPath} and {@code pathInfo}, which do not contain
 * path parameters (as defined in
 * <a href="https://www.ietf.org/rfc/rfc2396.txt">RFC 2396</a>). Different
 * servlet containers interpret the servlet spec differently as to how path
 * parameters are treated and it is possible they might be added in order to
 * bypass particular security constraints. When using this implementation, they
 * will be removed for all requests as the request passes through the security
 * filter chain. Note that this means that any segments in the decoded path
 * which contain a semi-colon, will have the part following the semi-colon
 * removed for request matching. Your application should not contain any valid
 * paths which contain semi-colons.
 * <p>
 * If any un-normalized paths are found (containing directory-traversal
 * character sequences), the request will be rejected immediately. Most
 * containers normalize the paths before performing the servlet-mapping, but
 * again this is not guaranteed by the servlet spec.
 *
 * @author Luke Taylor
 * @see StrictHttpFirewall
 */
public class DefaultHttpFirewall implements HttpFirewall {
	private boolean allowUrlEncodedSlash;

	@Override
	public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
		FirewalledRequest fwr = new RequestWrapper(request);

		if (!isNormalized(fwr.getServletPath()) || !isNormalized(fwr.getPathInfo())) {
			throw new RequestRejectedException("Un-normalized paths are not supported: " + fwr.getServletPath()
					+ (fwr.getPathInfo() != null ? fwr.getPathInfo() : ""));
		}

		String requestURI = fwr.getRequestURI();
		if (containsInvalidUrlEncodedSlash(requestURI)) {
			throw new RequestRejectedException("The requestURI cannot contain encoded slash. Got " + requestURI);
		}

		return fwr;
	}

	@Override
	public HttpServletResponse getFirewalledResponse(HttpServletResponse response) {
		return new FirewalledResponse(response);
	}

	/**
	 * <p>
	 * Sets if the application should allow a URL encoded slash character.
	 * </p>
	 * <p>
	 * If true (default is false), a URL encoded slash will be allowed in the
	 * URL. Allowing encoded slashes can cause security vulnerabilities in some
	 * situations depending on how the container constructs the
	 * HttpServletRequest.
	 * </p>
	 *
	 * @param allowUrlEncodedSlash the new value (default false)
	 */
	public void setAllowUrlEncodedSlash(boolean allowUrlEncodedSlash) {
		this.allowUrlEncodedSlash = allowUrlEncodedSlash;
	}

	private boolean containsInvalidUrlEncodedSlash(String uri) {
		if (this.allowUrlEncodedSlash || uri == null) {
			return false;
		}

		if (uri.contains("%2f") || uri.contains("%2F")) {
			return true;
		}

		return false;
	}

	/**
	 * Checks whether a path is normalized (doesn't contain path traversal
	 * sequences like "./", "/../" or "/.")
	 *
	 * @param path the path to test
	 * @return true if the path doesn't contain any path-traversal character
	 * sequences.
	 */
	private boolean isNormalized(String path) {
		if (path == null) {
			return true;
		}

		for (int j = path.length(); j > 0; ) {
			int i = path.lastIndexOf('/', j - 1);
			int gap = j - i;

			if (gap == 2 && path.charAt(i + 1) == '.') {
				// ".", "/./" or "/."
				return false;
			} else if (gap == 3 && path.charAt(i + 1) == '.' && path.charAt(i + 2) == '.') {
				return false;
			}

			j = i;
		}

		return true;
	}

}
