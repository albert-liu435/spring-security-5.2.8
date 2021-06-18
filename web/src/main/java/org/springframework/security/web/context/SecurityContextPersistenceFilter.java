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
package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 * https://andyboke.blog.csdn.net/article/details/84717438
 * SecurityContextPersistenceFilter有两个主要任务:
 * <p>
 * 在请求到达时处理之前，从SecurityContextRepository中获取安全上下文信息填充到SecurityContextHolder;
 * 在请求处理结束后返回响应时，将SecurityContextHolder中的安全上下文信息保存回SecurityContextRepository,并清空SecurityContextHolder。
 * 通过SecurityContextPersistenceFilter的这种机制，在整个请求处理过程中，开发人员都可以通过使用SecurityContextHolder获取当前访问用户的安全上下文信息。
 * <p>
 * 缺省情况下，SecurityContextPersistenceFilter使用的SecurityContextRepository是HttpSessionSecurityContextRepository，也就是将安全上下文的信息保存在用户的会话中。
 * <p>
 * 为了解决不同Serlvet容器上，尤其是weblogic上的兼容性问题，此Filter必须在整个request处理过程中被调用最多一次。
 * <p>
 * 该Filter也必须在任何认证机制逻辑发生之前被调用。因为这些认证机制都依赖于SecurityContextHolder所包含的安全上下文对象。
 * <p>
 * https://blog.csdn.net/fengyilin_henu/article/details/84916822
 * <p>
 * 试想一下，如果我们不使用 Spring Security，如果保存用户信息呢，大多数情况下会考虑使用 Session 对吧？在 Spring Security 中也是如此，用户在登录过一次之后，后续的访问便是通过 sessionId 来识别，从而认为用户已经被认证。具体在何处存放用户信息，
 * 便是第一篇文章中提到的 SecurityContextHolder；认证相关的信息是如何被存放到其中的，便是通过 SecurityContextPersistenceFilter。在 4.1 概述中也提到了，
 * SecurityContextPersistenceFilter 的两个主要作用便是请求来临时，创建 SecurityContext 安全上下文信息和请求结束时清空 SecurityContextHolder。顺带提一下：微服务的一个设计理念需要实现服务通信的无状态，而 http 协议中的无状态意味着不允许存在 session，
 * 这可以通过 setAllowSessionCreation(false) 实现，这并不意味着 SecurityContextPersistenceFilter 变得无用，因为它还需要负责清除用户信息。在 Spring Security 中，虽然安全上下文信息被存储于 Session 中，但我们在实际使用中不应该直接操作 Session，而应当使用 SecurityContextHolder。
 * <p>
 * 两个主要职责：请求来临时，创建 SecurityContext 安全上下文信息，请求结束时清空 SecurityContextHolder
 * <p>
 * 用来持久化SecurityContext实例用
 * <p>
 * 请求开始时从对应的SecurityContextRepository获取securityContext存入SecurityContextHolder中
 * 请求结束时清除SecurityContextHolder中的securityContext，将本次请求执行后新的SecurityContext存入到对应的SecurityContextRepository中
 * <p>
 * 其中在请求结束后清除SecurityContextHolder中的SecurityContext的操作是必须的，因为默认情况下SecurityContextHolder会把SecurityContext存储到ThreadLocal中，
 * 而这个thread刚好是存在于servlet容器的线程池中的，如果不清除，当后续请求又从线程池中分到这个线程时，程序就会拿到错误的认证信息。
 * <p>
 * SecurityContextPersistenceFilter 主要控制 SecurityContext 的在一次请求中的生命周期 。 请求来临时，创建SecurityContext 安全上下文信息，请求结束时清空 SecurityContextHolder。
 * <p>
 * SecurityContextPersistenceFilter 通过 HttpScurity#securityContext() 及相关方法引入其配置对象 SecurityContextConfigurer 来进行配置。
 * Populates the {@link SecurityContextHolder} with information obtained from the
 * configured {@link SecurityContextRepository} prior to the request and stores it back in
 * the repository once the request has completed and clearing the context holder. By
 * default it uses an {@link HttpSessionSecurityContextRepository}. See this class for
 * information <tt>HttpSession</tt> related configuration options.
 * <p>
 * This filter will only execute once per request, to resolve servlet container
 * (specifically Weblogic) incompatibilities.
 * <p>
 * This filter MUST be executed BEFORE any authentication processing mechanisms.
 * Authentication processing mechanisms (e.g. BASIC, CAS processing filters etc) expect
 * the <code>SecurityContextHolder</code> to contain a valid <code>SecurityContext</code>
 * by the time they execute.
 * <p>
 * This is essentially a refactoring of the old
 * <tt>HttpSessionContextIntegrationFilter</tt> to delegate the storage issues to a
 * separate strategy, allowing for more customization in the way the security context is
 * maintained between requests.
 * <p>
 * The <tt>forceEagerSessionCreation</tt> property can be used to ensure that a session is
 * always available before the filter chain executes (the default is <code>false</code>,
 * as this is resource intensive and not recommended).
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SecurityContextPersistenceFilter extends GenericFilterBean {

	//FILTER_APPLIED
	// 确保该Filter在一个request处理过程中最多被调到用一次的机制：
	// 一旦该Fitler被调用过，他会在当前request增加该属性值为true，利用此标记
	// 可以避免Filter被调用二次。
	static final String FILTER_APPLIED = "__spring_security_scpf_applied";
	// 安全上下文存储的仓库
	private SecurityContextRepository repo;

	private boolean forceEagerSessionCreation = false;

	public SecurityContextPersistenceFilter() {
		//HttpSessionSecurityContextRepository 是 SecurityContextRepository 接口的一个实现类
		// 使用 HttpSession 来存储 SecurityContext
		// 缺省使用http session 作为安全上下文对象存储
		this(new HttpSessionSecurityContextRepository());
	}

	public SecurityContextPersistenceFilter(SecurityContextRepository repo) {
		this.repo = repo;
	}

	/**
	 * 首先执行该过滤器
	 *
	 * @param req
	 * @param res
	 * @param chain
	 * @throws IOException
	 * @throws ServletException
	 */
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (request.getAttribute(FILTER_APPLIED) != null) {
			// ensure that filter is only applied once per request
			// 检查调用标志，如果request上已经存在属性FILTER_APPLIED,
			// 表明该Filter在该request的处理过程中已经被调用过
			chain.doFilter(request, response);
			return;
		}

		final boolean debug = logger.isDebugEnabled();
		//设置Attribute
		// 设置该Filter已经被调用的标记
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		//默认为false
		if (forceEagerSessionCreation) {
			HttpSession session = request.getSession();

			if (debug && session.isNew()) {
				logger.debug("Eagerly created session: " + session.getId());
			}
		}
		// 包装 request，response
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request,
				response);
		// 从 Session 中获取安全上下文信息
		// 从安全上下文存储库(缺省是http session)中读取安全上下文对象
		SecurityContext contextBeforeChainExecution = repo.loadContext(holder);

		try {
			// 请求开始时，设置安全上下文信息，这样就避免了用户直接从 Session 中获取安全上下文信息
			// 设置安全上下文对象到SecurityContextHolder然后才继续Filter chain的调用
			SecurityContextHolder.setContext(contextBeforeChainExecution);

			chain.doFilter(holder.getRequest(), holder.getResponse());

		} finally {
			// 请求结束后，清空安全上下文信息
			SecurityContext contextAfterChainExecution = SecurityContextHolder
					.getContext();
			// Crucial removal of SecurityContextHolder contents - do this before anything
			// else.
			SecurityContextHolder.clearContext();
			repo.saveContext(contextAfterChainExecution, holder.getRequest(),
					holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);

			if (debug) {
				logger.debug("SecurityContextHolder now cleared, as request processing completed");
			}
		}
	}

	public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
		this.forceEagerSessionCreation = forceEagerSessionCreation;
	}
}
