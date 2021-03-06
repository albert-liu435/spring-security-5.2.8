/*
 * Copyright 2012-2019 the original author or authors.
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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;

/**
 * https://andyboke.blog.csdn.net/article/details/90511688
 * StrictHttpFirewall是Spring Security Web提供的一个HTTP防火墙(对应概念模型接口HttpFirewall)实现,该实现采用了严格模式，遇到任何可疑的请求，会通过抛出异常RequestRejectedException拒绝该请求。StrictHttpFirewall也是Spring Security Web在安全过滤器代理FilterChainProxy内置缺省使用的HTTP防火墙机制。
 * <p>
 * 该防火墙实现使用如下规则决定是否拒绝一个请求:
 * <p>
 * 不在HTTP method许可清单的请求会被拒绝。
 * <p>
 * HTTP method许可清单通过方法setAllowedHttpMethods(Collection)设置。
 * 缺省被允许的HTTP method有 [DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT]。
 * <p>
 * 如果请求URL 不是标准化(normalize)的URL则该请求会被拒绝，以避免安全限制被绕过。
 * <p>
 * 在StrictHttpFirewall中该规则不能被禁用，因为关掉该限制风险极高。一种想通过该规则又想尽量安全的替代方法，是在请求到达前对URL进行标准化处理。跟StrictHttpFirewall相对应的另外一个HttpFirewall实现是DefaultHttpFirewall，DefaultHttpFirewall中对请求URL的限制没有这一条，但是相应地安全性就下降了。
 * <p>
 * 这里需要提醒的是，对请求URL做标准化处理是一种比较"脆弱"的(fragile)手段。建议即使请求会被拒绝，也尽量不要对其URL做标准化。
 * <p>
 * 标准化的URL必须符合以下条件 :
 * 在其requestURI/contextPath/servletPath/pathInfo中，必须不能包含以下字符串序列之一 :
 * ["//","./","/…/","/."]
 * <p>
 * 如果请求URL 中包含不可打印ASCII字符则该请求会被拒绝。
 * <p>
 * 该规则不可关闭，因为对应风极高。
 * <p>
 * 有关知识点 :
 * <p>
 * requestURI : URL中去除协议,主机名,端口之后其余的部分,
 * contextPath : requestURI中对应webapp的部分,
 * servletPath ： requestURI中对应识别Servlet的部分
 * ,pathInfo : requestURI中去掉contextPath,servletPath剩下的部分
 * 如果请求URL（无论是URL编码前还是URL编码后)包含了分号(;或者%3b或者%3B)则该请求会被拒绝。
 * <p>
 * 通过开关函数setAllowSemicolon(boolean) 可以设置是否关闭该规则。缺省使用该规则。
 * <p>
 * 如果请求URL（无论是URL编码前还是URL编码后)包含了斜杠(%2f或者%2F)则该请求会被拒绝。
 * <p>
 * 通过开关函数setAllowUrlEncodedSlash(boolean) 可以设置是否关闭该规则。缺省使用该规则。
 * <p>
 * 如果请求URL（无论是URL编码前还是URL编码后)包含了反斜杠(\或者%5c或者%5B)则该请求会被拒绝。
 * <p>
 * 通过开关函数setAllowBackSlash(boolean) 可以设置是否关闭该规则。缺省使用该规则。
 * <p>
 * 如果请求URL在URL编码后包含了%25(URL编码了的百分号%),或者在URL编码前包含了百分号%则该请求会被拒绝。
 * <p>
 * 通过开关函数setAllowUrlEncodedPercent(boolean) 可以设置是否关闭该规则。缺省使用该规则。
 * <p>
 * 如果请求URL在URL编码后包含了URL编码的英文句号.(%2e或者%2E)则该请求会被拒绝。
 * <p>
 * 通过开关函数setAllowUrlEncodedPeriod(boolean) 可以设置是否关闭该规则。缺省使用该规则。
 * <p>
 * 注意：这里提到的"URL编码后"对应英文是URL encoded,"URL编码前"指的是未执行URL编码的原始URL字符串，或者是"URL编码后"的URL经过解码URL decode得到的URL字符串(应该等于原始URL字符串)。
 * <p>
 * A strict implementation of {@link HttpFirewall} that rejects any suspicious requests
 * with a {@link RequestRejectedException}.
 * </p>
 * <p>
 * The following rules are applied to the firewall:
 * </p>
 * <ul>
 * <li>
 * Rejects HTTP methods that are not allowed. This specified to block
 * <a href="https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)">HTTP Verb tampering and XST attacks</a>.
 * See {@link #setAllowedHttpMethods(Collection)}
 * </li>
 * <li>
 * Rejects URLs that are not normalized to avoid bypassing security constraints. There is
 * no way to disable this as it is considered extremely risky to disable this constraint.
 * A few options to allow this behavior is to normalize the request prior to the firewall
 * or using {@link DefaultHttpFirewall} instead. Please keep in mind that normalizing the
 * request is fragile and why requests are rejected rather than normalized.
 * </li>
 * <li>
 * Rejects URLs that contain characters that are not printable ASCII characters. There is
 * no way to disable this as it is considered extremely risky to disable this constraint.
 * </li>
 * <li>
 * Rejects URLs that contain semicolons. See {@link #setAllowSemicolon(boolean)}
 * </li>
 * <li>
 * Rejects URLs that contain a URL encoded slash. See
 * {@link #setAllowUrlEncodedSlash(boolean)}
 * </li>
 * <li>
 * Rejects URLs that contain a backslash. See {@link #setAllowBackSlash(boolean)}
 * </li>
 * <li>
 * Rejects URLs that contain a URL encoded percent. See
 * {@link #setAllowUrlEncodedPercent(boolean)}
 * </li>
 * <li>
 * Rejects hosts that are not allowed. See
 * {@link #setAllowedHostnames(Predicate)}
 * </li>
 * </ul>
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @see DefaultHttpFirewall
 * @since 4.2.4
 */
public class StrictHttpFirewall implements HttpFirewall {
	/**
	 * Used to specify to {@link #setAllowedHttpMethods(Collection)} that any HTTP method should be allowed.
	 */
	private static final Set<String> ALLOW_ANY_HTTP_METHOD = Collections.unmodifiableSet(Collections.emptySet());

	private static final String ENCODED_PERCENT = "%25";

	private static final String PERCENT = "%";

	private static final List<String> FORBIDDEN_ENCODED_PERIOD = Collections.unmodifiableList(Arrays.asList("%2e", "%2E"));

	private static final List<String> FORBIDDEN_SEMICOLON = Collections.unmodifiableList(Arrays.asList(";", "%3b", "%3B"));

	private static final List<String> FORBIDDEN_FORWARDSLASH = Collections.unmodifiableList(Arrays.asList("%2f", "%2F"));

	private static final List<String> FORBIDDEN_DOUBLE_FORWARDSLASH = Collections.unmodifiableList(Arrays.asList("//", "%2f%2f", "%2f%2F", "%2F%2f", "%2F%2F"));

	private static final List<String> FORBIDDEN_BACKSLASH = Collections.unmodifiableList(Arrays.asList("\\", "%5c", "%5C"));

	private Set<String> encodedUrlBlacklist = new HashSet<>();

	private Set<String> decodedUrlBlacklist = new HashSet<>();

	//默认运行请求的方法
	private Set<String> allowedHttpMethods = createDefaultAllowedHttpMethods();

	private Predicate<String> allowedHostnames = hostname -> true;

	public StrictHttpFirewall() {
		urlBlacklistsAddAll(FORBIDDEN_SEMICOLON);
		urlBlacklistsAddAll(FORBIDDEN_FORWARDSLASH);
		urlBlacklistsAddAll(FORBIDDEN_DOUBLE_FORWARDSLASH);
		urlBlacklistsAddAll(FORBIDDEN_BACKSLASH);

		this.encodedUrlBlacklist.add(ENCODED_PERCENT);
		this.encodedUrlBlacklist.addAll(FORBIDDEN_ENCODED_PERIOD);
		this.decodedUrlBlacklist.add(PERCENT);
	}

	/**
	 * setUnsafeAllowAnyHttpMethod 方法表示不做 HTTP 请求方法校验，也就是什么方法都可以过。或者也可以通过 setAllowedHttpMethods 方法来重新定义可以通过的方法。
	 * Sets if any HTTP method is allowed. If this set to true, then no validation on the HTTP method will be performed.
	 * This can open the application up to <a href="https://www.owasp.org/index.php/Test_HTTP_Methods_(OTG-CONFIG-006)">
	 * HTTP Verb tampering and XST attacks</a>
	 *
	 * @param unsafeAllowAnyHttpMethod if true, disables HTTP method validation, else resets back to the defaults. Default is false.
	 * @see #setAllowedHttpMethods(Collection)
	 * @since 5.1
	 */
	public void setUnsafeAllowAnyHttpMethod(boolean unsafeAllowAnyHttpMethod) {
		this.allowedHttpMethods = unsafeAllowAnyHttpMethod ? ALLOW_ANY_HTTP_METHOD : createDefaultAllowedHttpMethods();
	}

	/**
	 * 确定应允许哪些HTTP方法，默认如下
	 * <p>
	 * Determines which HTTP methods should be allowed. The default is to allow "DELETE", "GET", "HEAD", "OPTIONS",
	 * "PATCH", "POST", and "PUT".
	 * </p>
	 *
	 * @param allowedHttpMethods the case-sensitive collection of HTTP methods that are allowed.
	 * @see #setUnsafeAllowAnyHttpMethod(boolean)
	 * @since 5.1
	 */
	public void setAllowedHttpMethods(Collection<String> allowedHttpMethods) {
		if (allowedHttpMethods == null) {
			throw new IllegalArgumentException("allowedHttpMethods cannot be null");
		}
		if (allowedHttpMethods == ALLOW_ANY_HTTP_METHOD) {
			this.allowedHttpMethods = ALLOW_ANY_HTTP_METHOD;
		} else {
			this.allowedHttpMethods = new HashSet<>(allowedHttpMethods);
		}
	}

	/**
	 * <p>
	 * Determines if semicolon is allowed in the URL (i.e. matrix variables). The default
	 * is to disable this behavior because it is a common way of attempting to perform
	 * <a href="https://www.owasp.org/index.php/Reflected_File_Download">Reflected File Download Attacks</a>.
	 * It is also the source of many exploits which bypass URL based security.
	 * </p>
	 * <p>For example, the following CVEs are a subset of the issues related
	 * to ambiguities in the Servlet Specification on how to treat semicolons that
	 * led to CVEs:
	 * </p>
	 * <ul>
	 *     <li><a href="https://pivotal.io/security/cve-2016-5007">cve-2016-5007</a></li>
	 *     <li><a href="https://pivotal.io/security/cve-2016-9879">cve-2016-9879</a></li>
	 *     <li><a href="https://pivotal.io/security/cve-2018-1199">cve-2018-1199</a></li>
	 * </ul>
	 *
	 * <p>
	 * If you are wanting to allow semicolons, please reconsider as it is a very common
	 * source of security bypasses. A few common reasons users want semicolons and
	 * alternatives are listed below:
	 * </p>
	 * <ul>
	 * <li>Including the JSESSIONID in the path - You should not include session id (or
	 * any sensitive information) in a URL as it can lead to leaking. Instead use Cookies.
	 * </li>
	 * <li>Matrix Variables - Users wanting to leverage Matrix Variables should consider
	 * using HTTP parameters instead.
	 * </li>
	 * </ul>
	 *
	 * @param allowSemicolon should semicolons be allowed in the URL. Default is false
	 */
	public void setAllowSemicolon(boolean allowSemicolon) {
		if (allowSemicolon) {
			urlBlacklistsRemoveAll(FORBIDDEN_SEMICOLON);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_SEMICOLON);
		}
	}

	/**
	 * <p>
	 * Determines if a slash "/" that is URL encoded "%2F" should be allowed in the path
	 * or not. The default is to not allow this behavior because it is a common way to
	 * bypass URL based security.
	 * </p>
	 * <p>
	 * For example, due to ambiguities in the servlet specification, the value is not
	 * parsed consistently which results in different values in {@code HttpServletRequest}
	 * path related values which allow bypassing certain security constraints.
	 * </p>
	 *
	 * @param allowUrlEncodedSlash should a slash "/" that is URL encoded "%2F" be allowed
	 *                             in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedSlash(boolean allowUrlEncodedSlash) {
		if (allowUrlEncodedSlash) {
			urlBlacklistsRemoveAll(FORBIDDEN_FORWARDSLASH);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_FORWARDSLASH);
		}
	}

	/**
	 * <p>
	 * Determines if double slash "//" that is URL encoded "%2F%2F" should be allowed in the path or
	 * not. The default is to not allow.
	 * </p>
	 *
	 * @param allowUrlEncodedDoubleSlash should a slash "//" that is URL encoded "%2F%2F" be allowed
	 *                                   in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedDoubleSlash(boolean allowUrlEncodedDoubleSlash) {
		if (allowUrlEncodedDoubleSlash) {
			urlBlacklistsRemoveAll(FORBIDDEN_DOUBLE_FORWARDSLASH);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_DOUBLE_FORWARDSLASH);
		}
	}

	/**
	 * <p>
	 * Determines if a period "." that is URL encoded "%2E" should be allowed in the path
	 * or not. The default is to not allow this behavior because it is a frequent source
	 * of security exploits.
	 * </p>
	 * <p>
	 * For example, due to ambiguities in the servlet specification a URL encoded period
	 * might lead to bypassing security constraints through a directory traversal attack.
	 * This is because the path is not parsed consistently which results  in different
	 * values in {@code HttpServletRequest} path related values which allow bypassing
	 * certain security constraints.
	 * </p>
	 *
	 * @param allowUrlEncodedPeriod should a period "." that is URL encoded "%2E" be
	 *                              allowed in the path or not. Default is false.
	 */
	public void setAllowUrlEncodedPeriod(boolean allowUrlEncodedPeriod) {
		if (allowUrlEncodedPeriod) {
			this.encodedUrlBlacklist.removeAll(FORBIDDEN_ENCODED_PERIOD);
		} else {
			this.encodedUrlBlacklist.addAll(FORBIDDEN_ENCODED_PERIOD);
		}
	}

	/**
	 * <p>
	 * Determines if a backslash "\" or a URL encoded backslash "%5C" should be allowed in
	 * the path or not. The default is not to allow this behavior because it is a frequent
	 * source of security exploits.
	 * </p>
	 * <p>
	 * For example, due to ambiguities in the servlet specification a URL encoded period
	 * might lead to bypassing security constraints through a directory traversal attack.
	 * This is because the path is not parsed consistently which results  in different
	 * values in {@code HttpServletRequest} path related values which allow bypassing
	 * certain security constraints.
	 * </p>
	 *
	 * @param allowBackSlash a backslash "\" or a URL encoded backslash "%5C" be allowed
	 *                       in the path or not. Default is false
	 */
	public void setAllowBackSlash(boolean allowBackSlash) {
		if (allowBackSlash) {
			urlBlacklistsRemoveAll(FORBIDDEN_BACKSLASH);
		} else {
			urlBlacklistsAddAll(FORBIDDEN_BACKSLASH);
		}
	}

	/**
	 * <p>
	 * Determines if a percent "%" that is URL encoded "%25" should be allowed in the path
	 * or not. The default is not to allow this behavior because it is a frequent source
	 * of security exploits.
	 * </p>
	 * <p>
	 * For example, this can lead to exploits that involve double URL encoding that lead
	 * to bypassing security constraints.
	 * </p>
	 *
	 * @param allowUrlEncodedPercent if a percent "%" that is URL encoded "%25" should be
	 *                               allowed in the path or not. Default is false
	 */
	public void setAllowUrlEncodedPercent(boolean allowUrlEncodedPercent) {
		if (allowUrlEncodedPercent) {
			this.encodedUrlBlacklist.remove(ENCODED_PERCENT);
			this.decodedUrlBlacklist.remove(PERCENT);
		} else {
			this.encodedUrlBlacklist.add(ENCODED_PERCENT);
			this.decodedUrlBlacklist.add(PERCENT);
		}
	}

	/**
	 * <p>
	 * Determines which hostnames should be allowed. The default is to allow any hostname.
	 * </p>
	 *
	 * @param allowedHostnames the predicate for testing hostnames
	 * @since 5.2
	 */
	public void setAllowedHostnames(Predicate<String> allowedHostnames) {
		if (allowedHostnames == null) {
			throw new IllegalArgumentException("allowedHostnames cannot be null");
		}
		this.allowedHostnames = allowedHostnames;
	}

	private void urlBlacklistsAddAll(Collection<String> values) {
		this.encodedUrlBlacklist.addAll(values);
		this.decodedUrlBlacklist.addAll(values);
	}

	private void urlBlacklistsRemoveAll(Collection<String> values) {
		this.encodedUrlBlacklist.removeAll(values);
		this.decodedUrlBlacklist.removeAll(values);
	}

	/**
	 * 将请求转换为FirewalledRequest
	 *
	 * @param request
	 * @return
	 * @throws RequestRejectedException
	 */
	@Override
	public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
		rejectForbiddenHttpMethod(request);
		rejectedBlacklistedUrls(request);
		rejectedUntrustedHosts(request);

		if (!isNormalized(request)) {
			throw new RequestRejectedException("The request was rejected because the URL was not normalized.");
		}

		String requestUri = request.getRequestURI();
		if (!containsOnlyPrintableAsciiCharacters(requestUri)) {
			throw new RequestRejectedException("The requestURI was rejected because it can only contain printable ASCII characters.");
		}
		return new FirewalledRequest(request) {
			@Override
			public void reset() {
			}
		};
	}

	private void rejectForbiddenHttpMethod(HttpServletRequest request) {
		if (this.allowedHttpMethods == ALLOW_ANY_HTTP_METHOD) {
			return;
		}
		if (!this.allowedHttpMethods.contains(request.getMethod())) {
			throw new RequestRejectedException("The request was rejected because the HTTP method \"" +
					request.getMethod() +
					"\" was not included within the whitelist " +
					this.allowedHttpMethods);
		}
	}

	private void rejectedBlacklistedUrls(HttpServletRequest request) {
		for (String forbidden : this.encodedUrlBlacklist) {
			if (encodedUrlContains(request, forbidden)) {
				throw new RequestRejectedException("The request was rejected because the URL contained a potentially malicious String \"" + forbidden + "\"");
			}
		}
		for (String forbidden : this.decodedUrlBlacklist) {
			if (decodedUrlContains(request, forbidden)) {
				throw new RequestRejectedException("The request was rejected because the URL contained a potentially malicious String \"" + forbidden + "\"");
			}
		}
	}

	private void rejectedUntrustedHosts(HttpServletRequest request) {
		String serverName = request.getServerName();
		if (serverName != null && !this.allowedHostnames.test(serverName)) {
			throw new RequestRejectedException("The request was rejected because the domain " + serverName + " is untrusted.");
		}
	}

	@Override
	public HttpServletResponse getFirewalledResponse(HttpServletResponse response) {
		return new FirewalledResponse(response);
	}

	/**
	 * 你的 HTTP 请求方法必须是 DELETE、GET、HEAD、OPTIONS、PATCH、POST 以及 PUT 中的一个，请求才能发送成功，否则的话，就会抛出 RequestRejectedException 异常。
	 *
	 * @return
	 */
	private static Set<String> createDefaultAllowedHttpMethods() {
		Set<String> result = new HashSet<>();
		result.add(HttpMethod.DELETE.name());
		result.add(HttpMethod.GET.name());
		result.add(HttpMethod.HEAD.name());
		result.add(HttpMethod.OPTIONS.name());
		result.add(HttpMethod.PATCH.name());
		result.add(HttpMethod.POST.name());
		result.add(HttpMethod.PUT.name());
		return result;
	}

	private static boolean isNormalized(HttpServletRequest request) {
		if (!isNormalized(request.getRequestURI())) {
			return false;
		}
		if (!isNormalized(request.getContextPath())) {
			return false;
		}
		if (!isNormalized(request.getServletPath())) {
			return false;
		}
		if (!isNormalized(request.getPathInfo())) {
			return false;
		}
		return true;
	}

	private static boolean encodedUrlContains(HttpServletRequest request, String value) {
		if (valueContains(request.getContextPath(), value)) {
			return true;
		}
		return valueContains(request.getRequestURI(), value);
	}

	private static boolean decodedUrlContains(HttpServletRequest request, String value) {
		if (valueContains(request.getServletPath(), value)) {
			return true;
		}
		if (valueContains(request.getPathInfo(), value)) {
			return true;
		}
		return false;
	}

	private static boolean containsOnlyPrintableAsciiCharacters(String uri) {
		int length = uri.length();
		for (int i = 0; i < length; i++) {
			char c = uri.charAt(i);
			if (c < '\u0020' || c > '\u007e') {
				return false;
			}
		}

		return true;
	}

	private static boolean valueContains(String value, String contains) {
		return value != null && value.contains(contains);
	}

	/**
	 * // 检测一个路径参数path是否是一个标准化了的路径 :
	 * // 1. 如果路径中包含连续两个反斜杠 "//" 则会被认为是非标准化的
	 * // 2. 如果路径中包含 "./" , "/../" , 或者 "/." , 则会被认为是非标准化的
	 * Checks whether a path is normalized (doesn't contain path traversal
	 * sequences like "./", "/../" or "/.")
	 *
	 * @param path the path to test
	 * @return true if the path doesn't contain any path-traversal character
	 * sequences.
	 */
	private static boolean isNormalized(String path) {
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

	/**
	 * Provides the existing encoded url blacklist which can add/remove entries from
	 *
	 * @return the existing encoded url blacklist, never null
	 */
	public Set<String> getEncodedUrlBlacklist() {
		return encodedUrlBlacklist;
	}

	/**
	 * Provides the existing decoded url blacklist which can add/remove entries from
	 *
	 * @return the existing decoded url blacklist, never null
	 */
	public Set<String> getDecodedUrlBlacklist() {
		return decodedUrlBlacklist;
	}
}
