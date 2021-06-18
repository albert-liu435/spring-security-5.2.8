/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * https://andyboke.blog.csdn.net/article/details/82111647
 * WebSecurity是Spring Security的一个SecurityBuilder。它的任务是基于一组WebSecurityConfigurer构建出一个Servlet Filter,具体来讲就是构建一个Spring Security的FilterChainProxy实例。这个FilterChainProxy实现了Filter接口，也是通常我们所说的Spring Security Filter Chain,所构建的FilterChainProxy实例缺省会使用名称springSecurityFilterChain作为bean注册到容器，运行时处理web请求过程中会使用该bean进行安全控制。
 * <p>
 * 每个FilterChainProxy包装了一个HttpFirewall和若干个SecurityFilterChain, 这里每个 SecurityFilterChain要么对应于一个要忽略安全控制的URL通配符(RequestMatcher)；要么对应于一个要进行安全控制的URL通配符(HttpSecurity)。
 * <p>
 * 助记公式 : 1 FilterChainProxy = 1 HttpFirewall + n SecurityFilterChain
 * <p>
 * WebSecurity构建目标FilterChainProxy所使用的WebSecurityConfigurer实现类通常会继承自WebSecurityConfigurerAdapter(当然也可以完全实现接口WebSecurityConfigurer)。每个WebSecurityConfigurerAdapter可以配置若干个要忽略安全控制的URL通配符(RequestMatcher)和一个要进行安全控制的URL通配符(HttpSecurity)。
 * <p>
 * 助记公式 :
 * 1 WebSecurity = 1 HttpFirewall + x HttpSecurity (securityFilterChainBuilders) + y RequestMatcher (ignoredRequests)
 * <p>
 * 这里 1 HttpSecurity 对应1个URL pattern,用于匹配一组需要进行安全配置的请求；
 * 这里 1 RequestMatcher 对应 1个URL pattern,用于匹配一组需要忽略安全控制的请求,比如静态公开资源或者其他动态公开资源；
 * 这里的每个 HttpSecurity或者RequestMatcher最终对应构建一个SecurityFilterChain,这里 x+y 会等于上面助记公式中的 n；
 * 1 WebSecurity最终用于构建1 FilterChainProxy, WebSecurity的HttpFirewall如果不存在，则目标FilterChainProxy会使用缺省值，一个StrictHttpFirewall；
 * 每个WebSecurity虽然允许设置多个securityFilterChainBuilder，但Spring Security在一个WebSecurityConfigurerAdapter中缺省只向其中添加一个securityFilterChainBuilder也就是HttpSecurity。
 * 开发人员可以在应用中提供多个WebSecurityConfigurerAdapter用于配置Spring Web Security，但要注意它们的优先级必须不同，这一点可以通过@Order注解来设置。
 * <p>
 * <p>
 * WebSecurity 由 WebSecurityConfiguration 创建，用于创建 FilterChainProxy, 这个 FilterChainProxy
 * 也就是通常我们所说的 Spring Security Filter Chain (springSecurityFilterChain)。
 * springSecurityFilterChain 是一个 Servlet 过滤器 Filter, DelegatingFilterProxy 会把真正的
 * 安全处理逻辑代理给这个 Filter 。
 * <p>
 * 通过创建一个或者多个 WebSecurityConfigurer, 或者重写 WebSecurityConfigurerAdapter 的某些方法，
 * 可以对 WebSecurity 进行定制。
 * The {@link WebSecurity} is created by {@link WebSecurityConfiguration} to create the
 * {@link FilterChainProxy} known as the Spring Security Filter Chain
 * (springSecurityFilterChain). The springSecurityFilterChain is the {@link Filter} that
 * the {@link DelegatingFilterProxy} delegates to.
 * </p>
 *
 * <p>
 * Customizations to the {@link WebSecurity} can be made by creating a
 * {@link WebSecurityConfigurer} or more likely by overriding
 * {@link WebSecurityConfigurerAdapter}.
 * </p>
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @see EnableWebSecurity
 * @see WebSecurityConfiguration
 * @since 3.2
 */
public final class WebSecurity extends
		AbstractConfiguredSecurityBuilder<Filter, WebSecurity> implements
		SecurityBuilder<Filter>, ApplicationContextAware {
	private final Log logger = LogFactory.getLog(getClass());
	// 记录开发人员通过类似下面例子语句指定忽略的URL :
	//  webSecurity.ignoring().antMatchers("/images/**", "/favicon.ico")
	// 在该例子中，会在 ignoredRequests 添加两个元素，分别对应 /images/**, /favicon.ico
	private final List<RequestMatcher> ignoredRequests = new ArrayList<>();
	// 最终被构建目标对象FilterChainProxy管理的多个安全过滤器链 SecurityFilterChain 的构建器列表，
	// 每个构建器用于构建一个 SecurityFilterChain
	private final List<SecurityBuilder<? extends SecurityFilterChain>> securityFilterChainBuilders = new ArrayList<>();
	//应该忽视的请求的配置
	private IgnoredRequestConfigurer ignoredRequestRegistry;

	private FilterSecurityInterceptor filterSecurityInterceptor;

	//Http防火墙功能
	private HttpFirewall httpFirewall;

	private boolean debugEnabled;

	private WebInvocationPrivilegeEvaluator privilegeEvaluator;
	// 初始化缺省的Web安全表达式处理器
	private DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
	// 实际使用的Web安全表达式处理器,缺省设置为使用缺省的Web安全表达式处理器
	private SecurityExpressionHandler<FilterInvocation> expressionHandler = defaultWebSecurityExpressionHandler;

	private Runnable postBuildAction = () -> {
	};

	/**
	 * Creates a new instance
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 * @see WebSecurityConfiguration
	 */
	public WebSecurity(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * 允许添加Spring security忽略的RequestMatcher实例
	 * <p>
	 * Allows adding {@link RequestMatcher} instances that Spring Security
	 * should ignore. Web Security provided by Spring Security (including the
	 * {@link SecurityContext}) will not be available on {@link HttpServletRequest} that
	 * match. Typically the requests that are registered should be that of only static
	 * resources. For requests that are dynamic, consider mapping the request to allow all
	 * users instead.
	 * </p>
	 * <p>
	 * Example Usage:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/ or /static/
	 * 		.antMatchers(&quot;/resources/**&quot;, &quot;/static/**&quot;);
	 * </pre>
	 * <p>
	 * Alternatively this will accomplish the same result:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/ or /static/
	 * 		.antMatchers(&quot;/resources/**&quot;).antMatchers(&quot;/static/**&quot;);
	 * </pre>
	 * <p>
	 * Multiple invocations of ignoring() are also additive, so the following is also
	 * equivalent to the previous two examples:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/
	 * 		.antMatchers(&quot;/resources/**&quot;);
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /static/
	 * 		.antMatchers(&quot;/static/**&quot;);
	 * // now both URLs that start with /resources/ and /static/ will be ignored
	 * </pre>
	 *
	 * @return the {@link IgnoredRequestConfigurer} to use for registering request that
	 * should be ignored
	 */
	public IgnoredRequestConfigurer ignoring() {
		return ignoredRequestRegistry;
	}

	/**
	 * Allows customizing the {@link HttpFirewall}. The default is
	 * {@link StrictHttpFirewall}.
	 *
	 * @param httpFirewall the custom {@link HttpFirewall}
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity httpFirewall(HttpFirewall httpFirewall) {
		this.httpFirewall = httpFirewall;
		return this;
	}

	/**
	 * 是否启用了调试模式，来自注解 @EnableWebSecurity 的属性 debug，缺省值 false
	 * Controls debugging support for Spring Security.
	 *
	 * @param debugEnabled if true, enables debug support with Spring Security. Default is
	 *                     false.
	 * @return the {@link WebSecurity} for further customization.
	 * @see EnableWebSecurity#debug()
	 */
	public WebSecurity debug(boolean debugEnabled) {
		this.debugEnabled = debugEnabled;
		return this;
	}

	/**
	 * 在构建Filter过程的初始化的时候，我们对securityFilterChainBuilders这个变量进行了赋值，默认情况下securityFilterChainBuilders里面只有一个对象，那就是HttpSecurity
	 * <p>
	 * 作者：怪诞140819
	 * 链接：https://www.jianshu.com/p/4fcdcf677371
	 * 来源：简书
	 * 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
	 * <p>
	 * Adds builders to create {@link SecurityFilterChain} instances.
	 * </p>
	 *
	 * <p>
	 * Typically this method is invoked automatically within the framework from
	 * {@link WebSecurityConfigurerAdapter#init(WebSecurity)}
	 * </p>
	 *
	 * @param securityFilterChainBuilder the builder to use to create the
	 *                                   {@link SecurityFilterChain} instances
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity addSecurityFilterChainBuilder(
			SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder) {
		//这个就是securityFilterChainBuilders变量

		this.securityFilterChainBuilders.add(securityFilterChainBuilder);
		return this;
	}

	/**
	 * Set the {@link WebInvocationPrivilegeEvaluator} to be used. If this is not specified,
	 * then a {@link DefaultWebInvocationPrivilegeEvaluator} will be created when
	 * {@link #securityInterceptor(FilterSecurityInterceptor)} is non null.
	 *
	 * @param privilegeEvaluator the {@link WebInvocationPrivilegeEvaluator} to use
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity privilegeEvaluator(
			WebInvocationPrivilegeEvaluator privilegeEvaluator) {
		this.privilegeEvaluator = privilegeEvaluator;
		return this;
	}

	/**
	 * 设置实际要使用的 SecurityExpressionHandler. 如果不设置，则缺省使用
	 * Set the {@link SecurityExpressionHandler} to be used. If this is not specified,
	 * then a {@link DefaultWebSecurityExpressionHandler} will be used.
	 *
	 * @param expressionHandler the {@link SecurityExpressionHandler} to use
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity expressionHandler(
			SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
		return this;
	}

	/**
	 * Gets the {@link SecurityExpressionHandler} to be used.
	 *
	 * @return the {@link SecurityExpressionHandler} for further customizations
	 */
	public SecurityExpressionHandler<FilterInvocation> getExpressionHandler() {
		return expressionHandler;
	}

	/**
	 * Gets the {@link WebInvocationPrivilegeEvaluator} to be used.
	 *
	 * @return the {@link WebInvocationPrivilegeEvaluator} for further customizations
	 */
	public WebInvocationPrivilegeEvaluator getPrivilegeEvaluator() {
		if (privilegeEvaluator != null) {
			return privilegeEvaluator;
		}
		return filterSecurityInterceptor == null ? null
				: new DefaultWebInvocationPrivilegeEvaluator(filterSecurityInterceptor);
	}

	/**
	 * Sets the {@link FilterSecurityInterceptor}. This is typically invoked by
	 * {@link WebSecurityConfigurerAdapter}.
	 *
	 * @param securityInterceptor the {@link FilterSecurityInterceptor} to use
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity securityInterceptor(FilterSecurityInterceptor securityInterceptor) {
		this.filterSecurityInterceptor = securityInterceptor;
		return this;
	}

	/**
	 * 指定一段逻辑，以Runnable形式组织，在 build 完成后立即执行，该类实际上是放在 performBuild()
	 * 函数结束前执行的
	 * Executes the Runnable immediately after the build takes place
	 *
	 * @param postBuildAction
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity postBuildAction(Runnable postBuildAction) {
		this.postBuildAction = postBuildAction;
		return this;
	}

	/**
	 * 这个方法中最主要的任务就是遍历securityFilterChainBuilders属性中的SecurityBuilder对象，并调用他的build方法。
	 * 这个securityFilterChainBuilders属性我们前面也有提到过，就是在WebSecurityConfigurerAdapter类的init方法中获取http后赋值给了WebSecurity。因此这个地方就是调用httpSecurity的build方法
	 * 各种配置信息已经搜集齐备，通过该方法执行构建过程，构建 Filter FilterChainProxy 实例并返回该 Filter
	 *
	 * @return
	 * @throws Exception
	 */
	@Override
	protected Filter performBuild() throws Exception {
		Assert.state(
				//T1  securityFilterChainBuilders哪里来的?
				!securityFilterChainBuilders.isEmpty(),
				() -> "At least one SecurityBuilder<? extends SecurityFilterChain> needs to be specified. "
						+ "Typically this done by adding a @Configuration that extends WebSecurityConfigurerAdapter. "
						+ "More advanced users can invoke "
						+ WebSecurity.class.getSimpleName()
						+ ".addSecurityFilterChainBuilder directly");
		//T2 ignoredRequests.size()到底是什么？
		// 计算出要创建的过滤器链 SecurityFilterChain 的个数 :
		// ignoredRequests 中URL通配符的个数 + securityFilterChainBuilders元素的个数，
		// 这里每个 securityFilterChainBuilders 元素实际上是一个 HttpSecurity
		int chainSize = ignoredRequests.size() + securityFilterChainBuilders.size();
		//这个securityFilterChains 的集合里面存放的就是我们所有的过滤器链，根据长度的定义，我们也可以知道分为两种
		// 一个是通过ignoredRequests来的过滤器链,一个是通过securityFilterChainBuilders这个过滤器链构建链来的。
		// 对于每个要忽略的URL通配符，构建一个 SecurityFilterChain 实例，使用的实现类为
		// DefaultSecurityFilterChain , 该实现类实例初始化时不包含任何过滤器，从而对给定的URL，
		// 可以达到不对其进行安全检查的目的
		List<SecurityFilterChain> securityFilterChains = new ArrayList<>(
				chainSize);
		//如果是ignoredRequest类型的，那么久添加默认过滤器链(DefaultSecurityFilterChain)
		// 对每个 securityFilterChainBuilder 执行其构建过程，生成一个 securityFilterChain,
		// 这里每个 securityFilterChainBuilders 元素实际上是一个 HttpSecurity
		for (RequestMatcher ignoredRequest : ignoredRequests) {
			securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest));
		}
		//如果是securityFilterChainBuilder类型的，那么通过securityFilterChainBuilder的build()方法来构建过滤器链
		for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : securityFilterChainBuilders) {
			securityFilterChains.add(securityFilterChainBuilder.build());
		}
		//将过滤器链交给一个过滤器链代理对象,而这个代理对象就是返回回去的过滤器,后面的代码先不做交代。到这里为止，过滤器的过程已经结束
		//T3 什么是FilterChainProxy?
		// 由多个 SecurityFilterChain securityFilterChains 构造一个 FilterChainProxy，这就是最终要构建的
		// Filter : FilterChainProxy : springSecurityFilterChain
		FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
		if (httpFirewall != null) {
			filterChainProxy.setFirewall(httpFirewall);
		}
		// 对根据配置新建的 filterChainProxy 进行验证,
		// FilterChainProxy 的缺省验证器是一个 NullFilterChainValidator,相应的验证逻辑为空方法
		filterChainProxy.afterPropertiesSet();

		Filter result = filterChainProxy;
		if (debugEnabled) {
			logger.warn("\n\n"
					+ "********************************************************************\n"
					+ "**********        Security debugging is enabled.       *************\n"
					+ "**********    This may include sensitive information.  *************\n"
					+ "**********      Do not use in a production system!     *************\n"
					+ "********************************************************************\n\n");
			result = new DebugFilter(filterChainProxy);
		}
		postBuildAction.run();
		return result;
	}

	/**
	 * An {@link IgnoredRequestConfigurer} that allows optionally configuring the
	 * {@link MvcRequestMatcher#setMethod(HttpMethod)}
	 *
	 * @author Rob Winch
	 */
	public final class MvcMatchersIgnoredRequestConfigurer
			extends IgnoredRequestConfigurer {
		private final List<MvcRequestMatcher> mvcMatchers;

		private MvcMatchersIgnoredRequestConfigurer(ApplicationContext context,
				List<MvcRequestMatcher> mvcMatchers) {
			super(context);
			this.mvcMatchers = mvcMatchers;
		}

		public IgnoredRequestConfigurer servletPath(String servletPath) {
			for (MvcRequestMatcher matcher : this.mvcMatchers) {
				matcher.setServletPath(servletPath);
			}
			return this;
		}
	}

	/**
	 * 注册RequestMatcher实例，并应被Spring Security安全框架忽视的请求
	 * <p>
	 * 嵌套类，用于注册 Spring Security 需要忽略的 RequestMatcher 实例
	 * Allows registering {@link RequestMatcher} instances that should be ignored by
	 * Spring Security.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	public class IgnoredRequestConfigurer
			extends AbstractRequestMatcherRegistry<IgnoredRequestConfigurer> {

		private IgnoredRequestConfigurer(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		public MvcMatchersIgnoredRequestConfigurer mvcMatchers(HttpMethod method,
				String... mvcPatterns) {
			List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
			WebSecurity.this.ignoredRequests.addAll(mvcMatchers);
			return new MvcMatchersIgnoredRequestConfigurer(getApplicationContext(),
					mvcMatchers);
		}

		@Override
		public MvcMatchersIgnoredRequestConfigurer mvcMatchers(String... mvcPatterns) {
			return mvcMatchers(null, mvcPatterns);
		}

		@Override
		protected IgnoredRequestConfigurer chainRequestMatchers(
				List<RequestMatcher> requestMatchers) {
			WebSecurity.this.ignoredRequests.addAll(requestMatchers);
			return this;
		}

		/**
		 * 返回当前 WebSecurity 实例，方便链式调用.
		 * Returns the {@link WebSecurity} to be returned for chaining.
		 */
		public WebSecurity and() {
			return WebSecurity.this;
		}
	}

	/**
	 * 设置应用上下文
	 *
	 * @param applicationContext
	 * @throws BeansException
	 */
	@Override
	public void setApplicationContext(ApplicationContext applicationContext)
			throws BeansException {
		this.defaultWebSecurityExpressionHandler
				.setApplicationContext(applicationContext);

		try {
			this.defaultWebSecurityExpressionHandler.setRoleHierarchy(applicationContext.getBean(RoleHierarchy.class));
		} catch (NoSuchBeanDefinitionException e) {
		}

		try {
			this.defaultWebSecurityExpressionHandler.setPermissionEvaluator(applicationContext.getBean(
					PermissionEvaluator.class));
		} catch (NoSuchBeanDefinitionException e) {
		}
		//创建需要忽视的请求
		this.ignoredRequestRegistry = new IgnoredRequestConfigurer(applicationContext);
		try {
			this.httpFirewall = applicationContext.getBean(HttpFirewall.class);
		} catch (NoSuchBeanDefinitionException e) {
		}
	}
}
