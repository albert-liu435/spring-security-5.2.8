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
package org.springframework.security.access.expression;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * https://blog.csdn.net/liuminglei1987/article/details/107413061
 * <p>
 * 用于Spring安全表达式计算的基根对象。
 * Base root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class SecurityExpressionRoot implements SecurityExpressionOperations {
	protected final Authentication authentication;
	private AuthenticationTrustResolver trustResolver;
	private RoleHierarchy roleHierarchy;
	private Set<String> roles;
	private String defaultRolePrefix = "ROLE_";

	/**
	 * Allows "permitAll" expression
	 */
	public final boolean permitAll = true;

	/**
	 * Allows "denyAll" expression
	 */
	public final boolean denyAll = false;
	private PermissionEvaluator permissionEvaluator;
	public final String read = "read";
	public final String write = "write";
	public final String create = "create";
	public final String delete = "delete";
	public final String admin = "administration";

	/**
	 * Creates a new instance
	 *
	 * @param authentication the {@link Authentication} to use. Cannot be null.
	 */
	public SecurityExpressionRoot(Authentication authentication) {
		if (authentication == null) {
			throw new IllegalArgumentException("Authentication object cannot be null");
		}
		this.authentication = authentication;
	}

	/**
	 * hasAuthority，对应 public final boolean hasAuthority(String authority) 方法，含义同 hasRole，不同点在于这是权限，而不是角色，区别就在于权限往往带有前缀（如默认的ROLE_），而角色只有标识。
	 *
	 * @param authority the authority to test (i.e. "ROLE_USER")
	 * @return
	 */
	public final boolean hasAuthority(String authority) {
		return hasAnyAuthority(authority);
	}

	/**
	 * hasAnyAuthority，对应 public final boolean hasAnyAuthority(String... authorities) 方法，含义同 hasAnyRole，不同点在于这是权限，而不是角色，区别就在于权限往往带有前缀（如默认的ROLE_），而角色只有标识
	 *
	 * @param authorities the authorities to test (i.e. "ROLE_USER", "ROLE_ADMIN")
	 * @return
	 */
	public final boolean hasAnyAuthority(String... authorities) {
		return hasAnyAuthorityName(null, authorities);
	}

	/**
	 * 用户具备某个角色即可访问资源
	 * hasRole，对应 public final boolean hasRole(String role) 方法，含义为必须含有某角色（非ROLE_开头），如有多个的话，必须同时具有这些角色，才可访问对应资源。
	 *
	 * @param role the authority to test (i.e. "USER")
	 * @return
	 */
	public final boolean hasRole(String role) {
		return hasAnyRole(role);
	}

	/**
	 * 用户具备多个角色中的任意一个即可访问资源
	 * hasAnyRole，对应 public final boolean hasAnyRole(String... roles) 方法，含义为只具有有某一角色（多多个角色的话，具有任意一个即可），即可访问对应资源。
	 *
	 * @param roles the authorities to test (i.e. "USER", "ADMIN")
	 * @return
	 */
	public final boolean hasAnyRole(String... roles) {
		return hasAnyAuthorityName(defaultRolePrefix, roles);
	}

	private boolean hasAnyAuthorityName(String prefix, String... roles) {
		Set<String> roleSet = getAuthoritySet();

		for (String role : roles) {
			String defaultedRole = getRoleWithDefaultPrefix(prefix, role);
			if (roleSet.contains(defaultedRole)) {
				return true;
			}
		}

		return false;
	}

	public final Authentication getAuthentication() {
		return authentication;
	}

	/**
	 * permitAll，对应 public final boolean permitAll() 方法，含义为允许所有人（可无任何权限）访问。
	 *
	 * @return
	 */
	public final boolean permitAll() {
		return true;
	}

	/**
	 * denyAll，对应 public final boolean denyAll() 方法，含义为不允许任何（即使有最大权限）访问。
	 *
	 * @return
	 */
	public final boolean denyAll() {
		return false;
	}

	/**
	 * isAnonymous，对应 public final boolean isAnonymous() 方法，含义为可匿名（不登录）访问。
	 *
	 * @return
	 */
	public final boolean isAnonymous() {
		return trustResolver.isAnonymous(authentication);
	}

	/**
	 * isAuthenticated，对应 public final boolean isAuthenticated() 方法，含义为身份证认证后访问。
	 *
	 * @return
	 */
	public final boolean isAuthenticated() {
		return !isAnonymous();
	}

	/**
	 * isRememberMe，对应 public final boolean isRememberMe() 方法，含义为记住我用户操作访问。
	 *
	 * @return
	 */
	public final boolean isRememberMe() {
		return trustResolver.isRememberMe(authentication);
	}

	/**
	 * isFullyAuthenticated，对应 public final boolean isFullyAuthenticated() 方法，含义为非匿名且非记住我用户允许访问。
	 *
	 * @return
	 */
	public final boolean isFullyAuthenticated() {
		return !trustResolver.isAnonymous(authentication)
				&& !trustResolver.isRememberMe(authentication);
	}

	/**
	 * Convenience method to access {@link Authentication#getPrincipal()} from
	 * {@link #getAuthentication()}
	 *
	 * @return
	 */
	public Object getPrincipal() {
		return authentication.getPrincipal();
	}

	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		this.trustResolver = trustResolver;
	}

	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		this.roleHierarchy = roleHierarchy;
	}

	/**
	 * <p>
	 * Sets the default prefix to be added to {@link #hasAnyRole(String...)} or
	 * {@link #hasRole(String)}. For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN")
	 * is passed in, then the role ROLE_ADMIN will be used when the defaultRolePrefix is
	 * "ROLE_" (default).
	 * </p>
	 *
	 * <p>
	 * If null or empty, then no default role prefix is used.
	 * </p>
	 *
	 * @param defaultRolePrefix the default prefix to add to roles. Default "ROLE_".
	 */
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		this.defaultRolePrefix = defaultRolePrefix;
	}

	private Set<String> getAuthoritySet() {
		if (roles == null) {
			Collection<? extends GrantedAuthority> userAuthorities = authentication
					.getAuthorities();

			if (roleHierarchy != null) {
				userAuthorities = roleHierarchy
						.getReachableGrantedAuthorities(userAuthorities);
			}

			roles = AuthorityUtils.authorityListToSet(userAuthorities);
		}

		return roles;
	}

	public boolean hasPermission(Object target, Object permission) {
		return permissionEvaluator.hasPermission(authentication, target, permission);
	}

	public boolean hasPermission(Object targetId, String targetType, Object permission) {
		return permissionEvaluator.hasPermission(authentication, (Serializable) targetId,
				targetType, permission);
	}

	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		this.permissionEvaluator = permissionEvaluator;
	}

	/**
	 * Prefixes role with defaultRolePrefix if defaultRolePrefix is non-null and if role
	 * does not already start with defaultRolePrefix.
	 *
	 * @param defaultRolePrefix
	 * @param role
	 * @return
	 */
	private static String getRoleWithDefaultPrefix(String defaultRolePrefix, String role) {
		if (role == null) {
			return role;
		}
		if (defaultRolePrefix == null || defaultRolePrefix.length() == 0) {
			return role;
		}
		if (role.startsWith(defaultRolePrefix)) {
			return role;
		}
		return defaultRolePrefix + role;
	}
}
