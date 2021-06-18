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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * https://andyboke.blog.csdn.net/article/details/84895467
 * <p>
 * 此过滤器过滤请求,检测SecurityContextHolder中是否存在Authentication对象，如果不存在，说明用户尚未登录，此时为其提供一个匿名Authentication对象:AnonymousAuthentication。
 * <p>
 * 注意:在整个请求处理的开始,无论当前请求所对应的session中用户是否已经登录,SecurityContextPersistenceFilter
 * 都会确保SecurityContextHolder中保持一个SecurityContext对象。但如果用户尚未登录，这个的SecurityContext对
 * 象会是一个空对象，也就是其属性Authentication为null。然后在该请求处理过程中，如果一直到当前Filter执
 * 行,SecurityContextHolder中SecurityContext对象属性Authentication仍是null,该AnonymousAuthenticationFilter就将其
 * 修改为一个AnonymousAuthentication对象，表明这是一个匿名访问。
 * <p>
 * <p>
 * 匿名身份过滤器，这个过滤器个人认为很重要，需要将它与 UsernamePasswordAuthenticationFilter 放在一起比较理解，spring security 为了兼容未登录的访问，也走了一套认证流程，只不过是一个匿名的身份
 * <p>
 * 匿名了还有身份？我自己对于 Anonymous 匿名身份的理解是 Spirng Security 为了整体逻辑的统一性，即使是未通过认证的用户，也给予了一个匿名身份。而 AnonymousAuthenticationFilter 该过滤器的位置也是非常的科学的，
 * 它位于常用的身份认证过滤器（如 UsernamePasswordAuthenticationFilter、BasicAuthenticationFilter、RememberMeAuthenticationFilter）之后，意味着只有在上述身份过滤器执行完毕后，SecurityContext 依旧没有用户信息，AnonymousAuthenticationFilter 该过滤器才会有意义 —- 基于用户一个匿名身份。
 * Detects if there is no {@code Authentication} object in the
 * {@code SecurityContextHolder}, and populates it with one if needed.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class AnonymousAuthenticationFilter extends GenericFilterBean implements
		InitializingBean {

	// ~ Instance fields
	// ================================================================================================
	// 用于构造匿名Authentication中详情属性的详情来源对象，这里使用一个WebAuthenticationDetailsSource
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private String key;
	private Object principal;
	private List<GrantedAuthority> authorities;

	/**
	 * // 自动创建一个 "anonymousUser" 的匿名用户, 其具有 ANONYMOUS 角色
	 * Creates a filter with a principal named "anonymousUser" and the single authority
	 * "ROLE_ANONYMOUS".
	 * 使用外部指定的key构造一个AnonymousAuthenticationFilter:
	 * 1. 缺省情况下，Spring Security 配置机制为这里指定的key是一个随机的uuid;
	 * 2. 所对应的 princpial(含义指当前登录主体) 是一个字符串"anonymousUser";
	 * 3. 所拥护的角色是 "ROLE_ANONYMOUS";
	 *
	 * @param key the key to identify tokens created by this filter
	 */
	public AnonymousAuthenticationFilter(String key) {
		this(key, "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	/**
	 * 使用外部指定的参数构造一个AnonymousAuthenticationFilter
	 *
	 * @param key         key the key to identify tokens created by this filter 用来识别该过滤器创建的身份
	 * @param principal   the principal which will be used to represent anonymous users 代表匿名用户的身份
	 * @param authorities the authority list for anonymous users 代表匿名用户的权限集合
	 */
	public AnonymousAuthenticationFilter(String key, Object principal,
			List<GrantedAuthority> authorities) {
		Assert.hasLength(key, "key cannot be null or empty");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
		this.key = key;
		this.principal = principal;
		this.authorities = authorities;
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public void afterPropertiesSet() {
		// 在当前Filter bean被创建时调用，主要目的是断言三个主要属性都必须已经有效设置
		Assert.hasLength(key, "key must have length");
		Assert.notNull(principal, "Anonymous authentication principal must be set");
		Assert.notNull(authorities, "Anonymous authorities must be set");
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		// 过滤器链都执行到匿名认证过滤器这儿了还没有身份信息，塞一个匿名身份进去
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			// 如果SecurityContextHolder中SecurityContext对象的属性authentication是null,
			// 将其替换成一个匿名 Authentication: AnonymousAuthentication
			SecurityContextHolder.getContext().setAuthentication(
					createAuthentication((HttpServletRequest) req));

			if (logger.isDebugEnabled()) {
				logger.debug("Populated SecurityContextHolder with anonymous token: '"
						+ SecurityContextHolder.getContext().getAuthentication() + "'");
			}
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("SecurityContextHolder not populated with anonymous token, as it already contained: '"
						+ SecurityContextHolder.getContext().getAuthentication() + "'");
			}
		}
// 对SecurityContextHolder中SecurityContext对象的属性authentication做过以上处理之后，继续
		// filter chain 的执行
		chain.doFilter(req, res);
	}

	// 根据指定属性key,princpial,authorities和当前环境(servlet web环境)构造一个AnonymousAuthenticationToken
	protected Authentication createAuthentication(HttpServletRequest request) {
		// 创建一个 AnonymousAuthenticationToken
		AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken(key,
				principal, authorities);
		auth.setDetails(authenticationDetailsSource.buildDetails(request));

		return auth;
	}

	// 可以外部指定Authentication对象的详情来源, 缺省情况下使用的是WebAuthenticationDetailsSource,
	// 已经在属性authenticationDetailsSource初始化指定
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource,
				"AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public Object getPrincipal() {
		return principal;
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}
}
