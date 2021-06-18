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

package org.springframework.security.access;

import java.util.Collection;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;

/**
 * https://blog.csdn.net/liuminglei1987/article/details/107904526
 *
 * https://www.jianshu.com/p/7e0302280468
 * <p>
 * 负责整个访问控制授权部分的投票策略和管理；
 * Makes a final access control (authorization) decision.
 * 用一句话描述他们的责任就是：AccessDecisionVoter负责对ConfigAttribute进行表决，AccessDecsionManager汇总表决，最终向框架返回最终的授权结果。
 *
 * @author Ben Alex
 */
public interface AccessDecisionManager {
	// ~ Methods
	// ========================================================================================================

	/**
	 * 决策 主要通过其持有的 AccessDecisionVoter 来进行投票决策
	 * decide方法接收三个参数，其中第一个参数中保存了当前登录用户的角色信息，第三个参数则是UrlFilterInvocationSecurityMetadataSource中的getAttributes方法传来的，表示当前请求需要的角色（可能有多个）。
	 * <p>
	 * Resolves an access control decision for the passed parameters.
	 *
	 * @param authentication   the caller invoking the method (not null)
	 * @param object           the secured object being called
	 * @param configAttributes the configuration attributes associated with the secured
	 *                         object being invoked
	 * @throws AccessDeniedException               if access is denied as the authentication does not
	 *                                             hold a required authority or ACL privilege
	 * @throws InsufficientAuthenticationException if access is denied as the
	 *                                             authentication does not provide a sufficient level of trust
	 */
	void decide(Authentication authentication, Object object,
			Collection<ConfigAttribute> configAttributes) throws AccessDeniedException,
			InsufficientAuthenticationException;

	/**
	 * 以确定AccessDecisionManager是否可以处理传递的ConfigAttribute
	 * Indicates whether this <code>AccessDecisionManager</code> is able to process
	 * authorization requests presented with the passed <code>ConfigAttribute</code>.
	 * <p>
	 * This allows the <code>AbstractSecurityInterceptor</code> to check every
	 * configuration attribute can be consumed by the configured
	 * <code>AccessDecisionManager</code> and/or <code>RunAsManager</code> and/or
	 * <code>AfterInvocationManager</code>.
	 * </p>
	 *
	 * @param attribute a configuration attribute that has been configured against the
	 *                  <code>AbstractSecurityInterceptor</code>
	 * @return true if this <code>AccessDecisionManager</code> can support the passed
	 * configuration attribute
	 */
	boolean supports(ConfigAttribute attribute);

	/**
	 * 以确保配置的AccessDecisionManager支持安全拦截器将呈现的安全 object 类型。
	 * Indicates whether the <code>AccessDecisionManager</code> implementation is able to
	 * provide access control decisions for the indicated secured object type.
	 *
	 * @param clazz the class that is being queried
	 * @return <code>true</code> if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);
}