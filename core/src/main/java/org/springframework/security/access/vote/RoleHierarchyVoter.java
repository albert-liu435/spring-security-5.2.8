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
package org.springframework.security.access.vote;

import java.util.Collection;

import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * 基于 RoleVoter，唯一的不同就是该投票器中的角色是附带上下级关系的。也就是说，角色A包含角色B，角色B包含 角色C，此时，如果用户拥有角色A，那么理论上可以同时拥有角色B、角色C的全部资源访问权限。
 * 通常要求应用程序中的特定角色应自动“包含”其他角色。例如，在具有 ROLE_ADMIN 和 ROLE_USER 角色概念的应用中，您可能希望管理员能够执行普通用户可以执行的所有操作。你不得不进行各种复杂的逻辑嵌套来满足这一需求。
 * 现在幸好有了 RoleHierarchyVoter 可以帮你减少这种负担。
 * 它由上面的 RoleVoter 派生,通过配置了一个 RoleHierarchy就可以实现 ROLE_ADMIN ⇒ ROLE_STAFF ⇒ ROLE_USER ⇒ ROLE_GUEST 这种层次包含结构，左边的一定能访问右边可以访问的资源。具体的配置规则为：角色从左到右、
 * 从高到低以 > 相连（注意两个空格），以换行符 \n 为分割线。举个例子
 * Extended RoleVoter which uses a {@link RoleHierarchy} definition to determine the roles
 * allocated to the current user before voting.
 *
 * @author Luke Taylor
 * @since 2.0.4
 */
public class RoleHierarchyVoter extends RoleVoter {
	private RoleHierarchy roleHierarchy = null;

	public RoleHierarchyVoter(RoleHierarchy roleHierarchy) {
		Assert.notNull(roleHierarchy, "RoleHierarchy must not be null");
		this.roleHierarchy = roleHierarchy;
	}

	/**
	 * Calls the <tt>RoleHierarchy</tt> to obtain the complete set of user authorities.
	 */
	@Override
	Collection<? extends GrantedAuthority> extractAuthorities(
			Authentication authentication) {
		return roleHierarchy.getReachableGrantedAuthorities(authentication
				.getAuthorities());
	}
}
