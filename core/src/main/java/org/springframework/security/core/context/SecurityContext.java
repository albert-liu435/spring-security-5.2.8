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

package org.springframework.security.core.context;

import org.springframework.security.core.Authentication;

import java.io.Serializable;

/**
 * https://andyboke.blog.csdn.net/article/details/91955225
 * <p>
 * Spring Security使用接口SecurityContext抽象建模"安全上下文"这一概念。这里安全上下文SecurityContext指的是当前执行线程使用的最少量的安全信息(其实就是用于代表访问者账号的有关信息)。当一个线程在服务用户期间，该安全上下文对象会保存在SecurityContextHolder中。
 * <p>
 * SecurityContextHolder类提供的功能是保持SecurityContext,不过它的用法不是让使用者创建多个SecurityContextHolder对象，而是提供一组公开静态工具方法。基于这组方法，SecurityContextHolder主要提供了两种管理SecurityContext的模式 :
 * <p>
 * 全局模式
 * 对整个应用公开保持一个SecurityContext,这种模式下,应用中的多个线程同一时间通过SecurityContextHolder访问到的都会是同一个SecurityContext对象;
 * <p>
 * 线程本地模式
 * 对应用中的某个线程保持一个SecurityContext,这种模式下，应用中的每个线程同一时间通过SecurityContextHolder访问到的都是关于自己线程的SecurityContext;
 * <p>
 * SecurityContext中保存的"最少量的安全信息"其实是通过Authentication对象所携带的信息。它用于代表当前访问者。如果当前访问者尚未认证但正在认证，Authentication内包含的是认证请求信息，比如用户名密码等等。如果当前访问者已经被认证，则Authentication会包含更多当前访问者的信息，比如权限，用户详情等等。另外即使访问者一直在访问一些不需要登录认证的公开资源，也有可能存在Authentication对象，此时Authentication会是一种特殊的类型，专门用于表示这是一个匿名用户。
 * <p>
 * Spring Security为接口SecurityContext提供了一个缺省实现SecurityContextImpl并在框架内各处缺省。
 * 定义与当前执行线程关联的最低安全信息的接口。
 * Interface defining the minimum security information associated with the current thread
 * of execution.
 * <p>
 * 安全上下文存储在SecurityContextHolder
 * <p>
 * The security context is stored in a {@link SecurityContextHolder}.
 * </p>
 *
 * @author Ben Alex
 */
public interface SecurityContext extends Serializable {
	// ~ Methods
	// ========================================================================================================

	/**
	 * 获取当前经过身份验证的主体或身份验证请求令牌。
	 * Obtains the currently authenticated principal, or an authentication request token.
	 *
	 * @return the <code>Authentication</code> or <code>null</code> if no authentication
	 * information is available
	 */
	Authentication getAuthentication();

	/**
	 * 更改当前经过身份验证的主体，或删除身份验证信息。
	 * Changes the currently authenticated principal, or removes the authentication
	 * information.
	 *
	 * @param authentication the new <code>Authentication</code> token, or
	 *                       <code>null</code> if no further authentication information should be stored
	 */
	void setAuthentication(Authentication authentication);
}
