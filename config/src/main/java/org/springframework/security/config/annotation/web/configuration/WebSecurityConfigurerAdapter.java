/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.TargetSource;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * https://andyboke.blog.csdn.net/article/details/90632411
 * WebSecurityConfigurerAdapter是Spring Security Config内置提供的一个WebSecurityConfigurer抽象实现类。WebSecurityConfigurerAdapter存在的目的是提供一个方便开发人员配置WebSecurity的基类。它提供了一组全方位配置WebSecurity的缺省方法实现。开发人员只要继承WebSecurityConfigurerAdapter提供自己的实现类，哪怕不覆盖WebSecurityConfigurerAdapter的任何一个方法，都得到了一个配置WebSecurity的安全配置器WebSecurityConfigurer实例。但通常情况下，开发人员都有自己特定的安全配置和要求，这时候就可以在自己提供的WebSecurityConfigurerAdapter子实现类中提供自己的方法覆盖WebSecurityConfigurerAdapter相应的方法从而对WebSecurity实施定制。
 * <p>
 * WebSecurityConfigurerAdapter为开发人员提供了如下功能 :
 * <p>
 * 构建一个用于配置WebSecurity的WebSecurityConfigurerAdapter对象，可以指定使用或者不使用缺省配置,默认构造函数使用缺省配置；
 * 提供可覆盖实现的方法void configure(AuthenticationManagerBuilder auth) ,允许开发人员配置目标WebSecurity所使用的AuthenticationManager的双亲AuthenticationManager；该方法缺省实现的效果是该双亲AuthenticationManager来自AuthenticationConfiguration定义的AuthenticationManager(其实是来自IoC容器的类型为AuthenticationManager的一个bean);
 * 通过覆盖实现该方法，开发人员可以定制认证机制，比如设置成基于内存的认证，基于数据库的认证，基于LDAP的认证，甚至这些认证机制的一个组合，设置AuthenticationManager的双亲关系，所使用的PasswordEncoder等等；
 * <p>
 * 提供可覆盖实现的空方法void configure(WebSecurity web)，允许开发人员覆盖实现配置WebSecurity,比如设置哪些URL要忽略安全等等；
 * 通过覆盖实现该方法，开发人员可以定制WebSecurity,主要是除了HttpSecurity之外的安全控制，比如忽略某些静态公开资源或者动态公开资源的安全 ,设置需要使用的防火墙实例，设置权限评估器，安全表达式处理器等;
 * <p>
 * WebSecurityConfigurerAdapter自身是一个WebSecurityConfigurer,它在自己的初始化方法init()中创建了HttpSecurity http安全构建器对象，并在缺省情况下(disableDefaults为false)应用了如下HttpSecurity初始配置:
 * <p>
 * <p>
 * <p>
 * 适配器模式在 spring 中被广泛的使用，在配置中使用 Adapter 的好处便是，我们可以选择性的配置想要修改的那一部分配置，而不用覆盖其他不相关的配置。WebSecurityConfigurerAdapter 中我们可以选择自己想要修改的内容，来进行重写，而其提供了三个 configure 重载方法
 * <p>
 * <p>
 * 用到了 @EnableWebSecurity注解，该注解和 @Configuration 注解一起使用, 注解 WebSecurityConfigurer 类型的类，
 * 或者利用@EnableWebSecurity 注解继承 WebSecurityConfigurerAdapter的类，这样就构成了 Spring Security 的配置。
 * WebSecurityConfigurerAdapter 提供了一种便利的方式去创建 WebSecurityConfigurer的实例，只需要重写 WebSecurityConfigurerAdapter 的方法，即可配置拦截什么URL、设置什么权限等安全控制。
 * <p>
 * 提供简单的方法用来创建WebSecurityConfigurer实例，可以通过实现类覆盖方法
 * Provides a convenient base class for creating a {@link WebSecurityConfigurer}
 * instance. The implementation allows customization by overriding methods.
 *
 * <p>
 * Will automatically apply the result of looking up
 * {@link AbstractHttpConfigurer} from {@link SpringFactoriesLoader} to allow
 * developers to extend the defaults.
 * To do this, you must create a class that extends AbstractHttpConfigurer and then create a file in the classpath at "META-INF/spring.factories" that looks something like:
 * </p>
 * <pre>
 * org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyClassThatExtendsAbstractHttpConfigurer
 * </pre>
 * If you have multiple classes that should be added you can use "," to separate the values. For example:
 *
 * <pre>
 * org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyClassThatExtendsAbstractHttpConfigurer, sample.OtherThatExtendsAbstractHttpConfigurer
 * </pre>
 *
 * @author Rob Winch
 * @see EnableWebSecurity
 */
@Order(100)
public abstract class WebSecurityConfigurerAdapter implements
		WebSecurityConfigurer<WebSecurity> {
	private final Log logger = LogFactory.getLog(WebSecurityConfigurerAdapter.class);

	private ApplicationContext context;

	private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
	// 在每个安全对象创建之后需要执行后置动作的 后置动作处理器，这里的缺省值
	// 其实只是抛出异常声明IoC容器中必须存在一个ObjectPostProcessor bean：
	// 参考 @EnableWebSecurity => @EnableGlobalAuthentication
	//       => AuthenticationConfiguration => ObjectPostProcessorConfiguration
	private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
		public <T> T postProcess(T object) {
			throw new IllegalStateException(
					ObjectPostProcessor.class.getName()
							+ " is a required bean. Ensure you have used @EnableWebSecurity and @Configuration");
		}
	};


	// 配置 WebSecurity 需要使用到的认证配置，可以认为是全局认证配置，会通过 set 方法被自动注入,
	// 该属性会用于从IoC容器获取目标 WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager 的双亲
	// AuthenticationManager 。 该方式可能用得上，也可能用不上，要看开发人员是配置使用
	// localConfigureAuthenticationBldr 还是使用该属性用于构建目标 WebSecurity/HttpSecurity 所要直接使用的
	// AuthenticationManager 的双亲 AuthenticationManager。
	private AuthenticationConfiguration authenticationConfiguration;
	// AuthenticationManager 构建器，缺省使用 : DefaultPasswordEncoderAuthenticationManagerBuilder
	// 所有构建的 AuthenticationManager 会是目标 WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager
	private AuthenticationManagerBuilder authenticationBuilder;
	// AuthenticationManager 构建器，缺省使用 : DefaultPasswordEncoderAuthenticationManagerBuilder
	// 所要构建的 AuthenticationManagerBuilder 会是目标 WebSecurity/HttpSecurity 所要直接使用的
	// AuthenticationManager 的双亲 AuthenticationManager。 不过缺省情况下，也就是开发人员不在子类
	// 中覆盖实现 void configure(AuthenticationManagerBuilder auth) 的情况下, 该 localConfigureAuthenticationBldr
	// 不会被用于构建目标 WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager 的双亲
	// AuthenticationManager, 这种情况下的双亲 AuthenticationManager 会来自 authenticationConfiguration
	private AuthenticationManagerBuilder localConfigureAuthenticationBldr;
	// 是否禁用 localConfigureAuthenticationBldr, 缺省情况下，也就是开发人员不在子类中覆盖实现
	// void configure(AuthenticationManagerBuilder auth) 的情况下,  当前 WebSecurityConfigurerAdapter
	// 缺省提供的 void configure(AuthenticationManagerBuilder auth)  方法实现会将该标志设置为 true,
	// 也就是不使用 localConfigureAuthenticationBldr 构建目标 WebSecurity/HttpSecurity 所要直接使用的
	// AuthenticationManager 的双亲 AuthenticationManager, 而是使用 authenticationConfiguration
	// 提供的 AuthenticationManager 作为 双亲 AuthenticationManager。
	private boolean disableLocalConfigureAuthenticationBldr;
	// 标志属性 : 目标 WebSecurity/HttpSecurity 所要直接使用的AuthenticationManager的双亲 authenticationManager
	// 是否已经初始化
	private boolean authenticationManagerInitialized;
	// 目标 WebSecurity/HttpSecurity 所要直接使用的AuthenticationManager的双亲 authenticationManager
	private AuthenticationManager authenticationManager;
	// 根据传入的 Authentication 的类型判断一个 Authentication 是否可被信任,
	// 缺省使用实现机制 AuthenticationTrustResolverImpl
	// 可被设置
	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
	// HTTP 安全构建器，用于配置匹配特定URL模式的控制器方法的安全，构建产物是 DefaultSecurityFilterChain
	private HttpSecurity http;
	// 是否禁用缺省配置,缺省为 false，可以通过当前类构造函数设置为true
	private boolean disableDefaults;

	/**
	 * Creates an instance with the default configuration enabled.
	 */
	protected WebSecurityConfigurerAdapter() {
		this(false);
	}

	/**
	 * Creates an instance which allows specifying if the default configuration should be
	 * enabled. Disabling the default configuration should be considered more advanced
	 * usage as it requires more understanding of how the framework is implemented.
	 *
	 * @param disableDefaults true if the default configuration should be disabled, else
	 *                        false
	 */
	protected WebSecurityConfigurerAdapter(boolean disableDefaults) {
		this.disableDefaults = disableDefaults;
	}

	/**
	 * Used by the default implementation of {@link #authenticationManager()} to attempt
	 * to obtain an {@link AuthenticationManager}. If overridden, the
	 * {@link AuthenticationManagerBuilder} should be used to specify the
	 * {@link AuthenticationManager}.
	 *
	 * <p>
	 * The {@link #authenticationManagerBean()} method can be used to expose the resulting
	 * {@link AuthenticationManager} as a Bean. The {@link #userDetailsServiceBean()} can
	 * be used to expose the last populated {@link UserDetailsService} that is created
	 * with the {@link AuthenticationManagerBuilder} as a Bean. The
	 * {@link UserDetailsService} will also automatically be populated on
	 * {@link HttpSecurity#getSharedObject(Class)} for use with other
	 * {@link SecurityContextConfigurer} (i.e. RememberMeConfigurer )
	 * </p>
	 *
	 * <p>
	 * For example, the following configuration could be used to register in memory
	 * authentication that exposes an in memory {@link UserDetailsService}:
	 * </p>
	 *
	 * <pre>
	 * &#064;Override
	 * protected void configure(AuthenticationManagerBuilder auth) {
	 * 	auth
	 * 	// enable in memory based authentication with a user named
	 * 	// &quot;user&quot; and &quot;admin&quot;
	 * 	.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;).and()
	 * 			.withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
	 * }
	 *
	 * // Expose the UserDetailsService as a Bean
	 * &#064;Bean
	 * &#064;Override
	 * public UserDetailsService userDetailsServiceBean() throws Exception {
	 * 	return super.userDetailsServiceBean();
	 * }
	 *
	 * </pre>
	 * 开发人员可以覆盖该方法用于配置指定的 AuthenticationManagerBuilder auth,
	 * 如果开发人员这么做了，那么这里所被配置的 auth , 其实就是当前配置器的属性
	 * localConfigureAuthenticationBldr 会被用于构建 WebSecurity/HttpSecurity
	 * 所要使用的 AuthenticationManager 的双亲 AuthenticationManager。
	 * 如果开发人员不覆盖实现此方法，此缺省实现其实只是设置一个禁用标志，禁用
	 * localConfigureAuthenticationBldr, 此时 WebSecurity/HttpSecurity 所要使
	 * 用的 AuthenticationManager 的双亲 AuthenticationManager 将会来自
	 * authenticationConfiguration.getAuthenticationManager()
	 *
	 * @param auth the {@link AuthenticationManagerBuilder} to use
	 * @throws Exception
	 */
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		this.disableLocalConfigureAuthenticationBldr = true;
	}

	/**
	 * https://www.jianshu.com/p/6f1b129442a1
	 * 创建或返回当前的HttpSecurity
	 * getHttp()方法，这个方法在当我们使用默认配置时（大多数情况下）会为我们追加各种SecurityConfigurer的具体实现类到httpSecurity中，如exceptionHandling()方法会追加一个ExceptionHandlingConfigurer，
	 * sessionManagement()方法会追加一个SessionManagementConfigurer,securityContext()方法会追加一个SecurityContextConfigurer对象，这些SecurityConfigurer的具体实现类最终会为我们配置各种具体的filter，
	 * 这些SecurityConfigurer类是怎么调用到的，下面会讲到
	 * 另外getHttp()方法的最后会调用configure(http)，这个方法也是我们继承WebSecurityConfigurerAdapter类后最可能会重写的方法
	 * Creates the {@link HttpSecurity} or returns the current instance
	 * <p>
	 * ] * @return the {@link HttpSecurity}
	 *
	 * @throws Exception
	 */
	@SuppressWarnings({"rawtypes", "unchecked"})
	protected final HttpSecurity getHttp() throws Exception {
		//如果已经存在HttpSecurity 对象，则返回
		if (http != null) {
			return http;
		}
		//
		DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor
				.postProcess(new DefaultAuthenticationEventPublisher());
		localConfigureAuthenticationBldr.authenticationEventPublisher(eventPublisher);
		//构建AuthenticationManager对象，这个对象管理认证
		// 获取 WebSecurity/HttpSecurity 所要直接使用的  AuthenticationManager
		// 的双亲 AuthenticationManager
		AuthenticationManager authenticationManager = authenticationManager();
		//  authenticationBuilder 所要构建的目标 AuthenticationManager 才是
		// 当前配置器所配置的 WebSecurity/HttpSecurity 所要直接使用的  AuthenticationManager
		authenticationBuilder.parentAuthenticationManager(authenticationManager);
		authenticationBuilder.authenticationEventPublisher(eventPublisher);
		//创建共享对象
		Map<Class<?>, Object> sharedObjects = createSharedObjects();
		//构建HttpSecurity 需要用到authenticationBuilder,sharedObjects
		http = new HttpSecurity(objectPostProcessor, authenticationBuilder,
				sharedObjects);
		//允许默认配置的时候,配置相关的Filter
		if (!disableDefaults) {
			// @formatter:off
			http
					.csrf().and()
					//添加Filter
					.addFilter(new WebAsyncManagerIntegrationFilter())
					.exceptionHandling().and()
					.headers().and()
					.sessionManagement().and()
					.securityContext().and()
					.requestCache().and()
					.anonymous().and()
					.servletApi().and()
					.apply(new DefaultLoginPageConfigurer<>()).and()
					.logout();
			// @formatter:on
			ClassLoader classLoader = this.context.getClassLoader();
			// 使用 SpringFactoriesLoader 加载 classpath 上所有jar包中各自的 META-INF/spring.factories 属性文件
			// 中指定的 AbstractHttpConfigurer,应用到 http
			List<AbstractHttpConfigurer> defaultHttpConfigurers =
					SpringFactoriesLoader.loadFactories(AbstractHttpConfigurer.class, classLoader);

			for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
				http.apply(configurer);
			}
		}
		// 使用方法 protected void configure(HttpSecurity http) 配置 HttpSecurity http ,
		// 这里如果开发人员重写了该方法，则这里这些开发人员配置逻辑会被应用于配置 HttpSecurity http ,
		configure(http);
		return http;
	}

	/**
	 * Override this method to expose the {@link AuthenticationManager} from
	 * {@link #configure(AuthenticationManagerBuilder)} to be exposed as a Bean. For
	 * example:
	 *
	 * <pre>
	 * &#064;Bean(name name="myAuthenticationManager")
	 * &#064;Override
	 * public AuthenticationManager authenticationManagerBean() throws Exception {
	 *     return super.authenticationManagerBean();
	 * }
	 * </pre>
	 *
	 * @return the {@link AuthenticationManager}
	 * @throws Exception
	 */
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return new AuthenticationManagerDelegator(authenticationBuilder, context);
	}

	/**
	 * 获取构建 WebSecurity/HttpSecurity所要使用的 AuthenticationManager 的
	 * 双亲 AuthenticationManager，这里的策略是 :
	 * 1. 如果开发人员覆盖实现了 #configure(AuthenticationManagerBuilder) ,
	 * 则会使用开发人员覆盖实现了的 AuthenticationManagerBuilder , 其实也就是
	 * 当前配置器的 localConfigureAuthenticationBldr 构建一个 AuthenticationManager
	 * 并返回和使用;
	 * 2. 如果开发人员没有覆盖实现 #configure(AuthenticationManagerBuilder) ,
	 * 则会使用  authenticationConfiguration#getAuthenticationManager() 提供的
	 * Gets the {@link AuthenticationManager} to use. The default strategy is if
	 * {@link #configure(AuthenticationManagerBuilder)} method is overridden to use the
	 * {@link AuthenticationManagerBuilder} that was passed in. Otherwise, autowire the
	 * {@link AuthenticationManager} by type.
	 *
	 * @return the {@link AuthenticationManager} to use
	 * @throws Exception
	 */
	protected AuthenticationManager authenticationManager() throws Exception {
		if (!authenticationManagerInitialized) {
			//  authenticationManager 尚未初始化的情况，在这里进行初始化

			// 调用 configure(AuthenticationManagerBuilder auth) 用于配置  localConfigureAuthenticationBldr,
			// 该方法有可能被开发人员覆盖实现
			configure(localConfigureAuthenticationBldr);
			if (disableLocalConfigureAuthenticationBldr) {
				// 如果开发人员没有覆盖实现 configure(AuthenticationManagerBuilder auth)
				// 方法， 则该方法的缺省实现会设置 disableLocalConfigureAuthenticationBldr=true,
				// 这种情况下会使用 authenticationConfiguration 获取IoC容器中配置的 AuthenticationManager
				// 作为目标WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager 的双亲
				authenticationManager = authenticationConfiguration
						.getAuthenticationManager();
			} else {
				// 如果开发人员覆盖实现了 configure(AuthenticationManagerBuilder auth)
				// 方法，则 localConfigureAuthenticationBldr 会被用于构建一个 AuthenticationManager,
				// 该 AuthenticationManager 会充当目标WebSecurity/HttpSecurity 所要直接使用的
				// AuthenticationManager 的双亲
				authenticationManager = localConfigureAuthenticationBldr.build();
			}
			//  authenticationManager 初始化完成的情况，设置相应标志
			authenticationManagerInitialized = true;
		}
		return authenticationManager;
	}

	/**
	 * Override this method to expose a {@link UserDetailsService} created from
	 * {@link #configure(AuthenticationManagerBuilder)} as a bean. In general only the
	 * following override should be done of this method:
	 *
	 * <pre>
	 * &#064;Bean(name = &quot;myUserDetailsService&quot;)
	 * // any or no name specified is allowed
	 * &#064;Override
	 * public UserDetailsService userDetailsServiceBean() throws Exception {
	 * 	return super.userDetailsServiceBean();
	 * }
	 * </pre>
	 * <p>
	 * To change the instance returned, developers should change
	 * {@link #userDetailsService()} instead
	 *
	 * @return the {@link UserDetailsService}
	 * @throws Exception
	 * @see #userDetailsService()
	 */
	public UserDetailsService userDetailsServiceBean() throws Exception {
		AuthenticationManagerBuilder globalAuthBuilder = context
				.getBean(AuthenticationManagerBuilder.class);
		return new UserDetailsServiceDelegator(Arrays.asList(
				localConfigureAuthenticationBldr, globalAuthBuilder));
	}

	/**
	 * Allows modifying and accessing the {@link UserDetailsService} from
	 * {@link #userDetailsServiceBean()} without interacting with the
	 * {@link ApplicationContext}. Developers should override this method when changing
	 * the instance of {@link #userDetailsServiceBean()}.
	 *
	 * @return the {@link UserDetailsService} to use
	 */
	protected UserDetailsService userDetailsService() {
		AuthenticationManagerBuilder globalAuthBuilder = context
				.getBean(AuthenticationManagerBuilder.class);
		return new UserDetailsServiceDelegator(Arrays.asList(
				localConfigureAuthenticationBldr, globalAuthBuilder));
	}

	/**
	 * init方法做了两件事，一个就是调用getHttp()方法获取一个http实例，并通过web.addSecurityFilterChainBuilder方法把获取到的实例
	 * 赋值给WebSecurity的securityFilterChainBuilders属性，这个属性在我们执行build的时候会用到，第二个就是为WebSecurity追加了一个postBuildAction，在build都完成后从http中拿出FilterSecurityInterceptor
	 * 对象并赋值给WebSecurity。
	 *
	 * @param web
	 * @throws Exception
	 */
	public void init(final WebSecurity web) throws Exception {
		//获取HttpSecurity
		//先构建HttpSecurity对象，然后通过WebSecurity对象的addSecurityFilterChainBuilder()方法添加到securityFilterChainBuilders的List中，最后用来组件过滤器链
		//
		//作者：怪诞140819
		//链接：https://www.jianshu.com/p/6f1b129442a1
		//来源：简书
		//著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
		final HttpSecurity http = getHttp();

		web.addSecurityFilterChainBuilder(http).postBuildAction(() -> {
			//这里构建了HttpSecurity对象，以及有一个共享对象FilterSecurityInterceptor
			FilterSecurityInterceptor securityInterceptor = http
					.getSharedObject(FilterSecurityInterceptor.class);
			web.securityInterceptor(securityInterceptor);
		});
	}

	/**
	 * Override this method to configure {@link WebSecurity}. For example, if you wish to
	 * ignore certain requests.
	 * <p>
	 * Endpoints specified in this method will be ignored by Spring Security, meaning it
	 * will not protect them from CSRF, XSS, Clickjacking, and so on.
	 * <p>
	 * Instead, if you want to protect endpoints against common vulnerabilities, then see
	 * {@link #configure(HttpSecurity)} and the {@link HttpSecurity#authorizeRequests}
	 * configuration method.
	 */
	public void configure(WebSecurity web) throws Exception {
	}

	/**
	 * 覆盖该方法用于配置HttpSecurity，
	 * configure(HttpSecurity http)方法，默认的configure(HttpSecurity http)方法继续向httpSecurity类中追加SecurityConfigurer的具体实现类，如authorizeRequests()方法追加一个ExpressionUrlAuthorizationConfigurer，
	 * formLogin()方法追加一个FormLoginConfigurer。
	 * 其中ExpressionUrlAuthorizationConfigurer这个实现类后面会进一步探讨，因为他会给我们创建一个非常重要的对象FilterSecurityInterceptor对象，FormLoginConfigurer对象比较简单，但是也会为我们提供一个
	 * 在安全认证过程中经常用到会用的一个Filter：UsernamePasswordAuthenticationFilter。
	 * Override this method to configure the {@link HttpSecurity}. Typically subclasses
	 * should not invoke this method by calling super as it may override their
	 * configuration. The default configuration is:
	 * 默认配置如下
	 * <pre>
	 * http.authorizeRequests().anyRequest().authenticated().and().formLogin().and().httpBasic();
	 * </pre>
	 * <p>
	 * Any endpoint that requires defense against common vulnerabilities can be specified here, including public ones.
	 * See {@link HttpSecurity#authorizeRequests} and the `permitAll()` authorization rule
	 * for more details on public endpoints.
	 *
	 * @param http the {@link HttpSecurity} to modify
	 * @throws Exception if an error occurs
	 */
	// @formatter:off
	protected void configure(HttpSecurity http) throws Exception {
		logger.debug("Using default configure(HttpSecurity). If subclassed this will potentially override subclass configure(HttpSecurity).");

		http
				//用来管理路径访问控制
				.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				//管理登录表单配置
				.formLogin().and()
				//是否基于Http的验证配置
				.httpBasic();
	}
	// @formatter:on

	/**
	 * Gets the ApplicationContext
	 *
	 * @return the context
	 */
	protected final ApplicationContext getApplicationContext() {
		return this.context;
	}

	/**
	 * 设置应用上下文ApplicationContext
	 *
	 * @param context
	 */
	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;
		//获取ObjectPostProcessor
		//AutowireBeanFactoryObjectPostProcessor
		ObjectPostProcessor<Object> objectPostProcessor = context.getBean(ObjectPostProcessor.class);
		//		// 密码加密器，口令加密器，使用当前  WebSecurityConfigurerAdapter 的内部嵌套类 LazyPasswordEncoder
		LazyPasswordEncoder passwordEncoder = new LazyPasswordEncoder(context);
		//获取默认的AuthenticationManagerBuilder
		// 目标 WebSecurity/HttpSecurity 所要直接使用的  AuthenticationManager 的构建器
		authenticationBuilder = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor, passwordEncoder);
		//// 目标 WebSecurity/HttpSecurity 所要直接使用的  AuthenticationManager  的双亲  AuthenticationManager
		//		// 的构建器, 可能被用的上，也可能用不上，要看开发人员是否决定使用这个 localConfigureAuthenticationBldr
		localConfigureAuthenticationBldr = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor, passwordEncoder) {
			/**
			 * 设置是否清除凭证
			 * @param eraseCredentials true if {@link AuthenticationManager} should clear the
			 *                         credentials from the {@link Authentication} object after authenticating
			 * @return
			 */
			@Override
			public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
				authenticationBuilder.eraseCredentials(eraseCredentials);
				return super.eraseCredentials(eraseCredentials);
			}

		};
	}

	// 依赖注入 AuthenticationTrustResolver ， 如果容器中有 AuthenticationTrustResolver bean
	// 则使用，否则则使用缺省值 : AuthenticationTrustResolverImpl
	@Autowired(required = false)
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		this.trustResolver = trustResolver;
	}

	// 依赖注入 ContentNegotiationStrategy ， 如果容器中有 ContentNegotiationStrategy bean
	// 则使用，否则则使用缺省值 : HeaderContentNegotiationStrategy
	@Autowired(required = false)
	public void setContentNegotationStrategy(
			ContentNegotiationStrategy contentNegotiationStrategy) {
		this.contentNegotiationStrategy = contentNegotiationStrategy;
	}

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@Autowired
	public void setAuthenticationConfiguration(
			AuthenticationConfiguration authenticationConfiguration) {
		this.authenticationConfiguration = authenticationConfiguration;
	}

	/**
	 * Creates the shared objects
	 *
	 * @return the shared Objects
	 */
	private Map<Class<?>, Object> createSharedObjects() {
		Map<Class<?>, Object> sharedObjects = new HashMap<>();
		sharedObjects.putAll(localConfigureAuthenticationBldr.getSharedObjects());
		sharedObjects.put(UserDetailsService.class, userDetailsService());
		sharedObjects.put(ApplicationContext.class, context);
		sharedObjects.put(ContentNegotiationStrategy.class, contentNegotiationStrategy);
		sharedObjects.put(AuthenticationTrustResolver.class, trustResolver);
		return sharedObjects;
	}

	/**
	 * Delays the use of the {@link UserDetailsService} from the
	 * {@link AuthenticationManagerBuilder} to ensure that it has been fully configured.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	static final class UserDetailsServiceDelegator implements UserDetailsService {
		private List<AuthenticationManagerBuilder> delegateBuilders;
		private UserDetailsService delegate;
		private final Object delegateMonitor = new Object();

		UserDetailsServiceDelegator(List<AuthenticationManagerBuilder> delegateBuilders) {
			if (delegateBuilders.contains(null)) {
				throw new IllegalArgumentException(
						"delegateBuilders cannot contain null values. Got "
								+ delegateBuilders);
			}
			this.delegateBuilders = delegateBuilders;
		}

		public UserDetails loadUserByUsername(String username)
				throws UsernameNotFoundException {
			if (delegate != null) {
				return delegate.loadUserByUsername(username);
			}

			synchronized (delegateMonitor) {
				if (delegate == null) {
					for (AuthenticationManagerBuilder delegateBuilder : delegateBuilders) {
						delegate = delegateBuilder.getDefaultUserDetailsService();
						if (delegate != null) {
							break;
						}
					}

					if (delegate == null) {
						throw new IllegalStateException("UserDetailsService is required.");
					}
					this.delegateBuilders = null;
				}
			}

			return delegate.loadUserByUsername(username);
		}
	}

	/**
	 * 内部嵌套类，该类的目的是包装一个 AuthenticationManager ， 该被包装的
	 * AuthenticationManager 会由该 AuthenticationManagerDelegator 的构造函数
	 * 参数对象 delegateBuilder 在目标 AuthenticationManager 首次被使用时构建。
	 * 这么做的目的是确保 AuthenticationManager 被调用时，它已经被完全配置。
	 * Delays the use of the {@link AuthenticationManager} build from the
	 * {@link AuthenticationManagerBuilder} to ensure that it has been fully configured.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {
		private AuthenticationManagerBuilder delegateBuilder;
		private AuthenticationManager delegate;
		private final Object delegateMonitor = new Object();
		private Set<String> beanNames;

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder,
				ApplicationContext context) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			Field parentAuthMgrField = ReflectionUtils.findField(
					AuthenticationManagerBuilder.class, "parentAuthenticationManager");
			ReflectionUtils.makeAccessible(parentAuthMgrField);
			beanNames = getAuthenticationManagerBeanNames(context);
			validateBeanCycle(
					ReflectionUtils.getField(parentAuthMgrField, delegateBuilder),
					beanNames);
			this.delegateBuilder = delegateBuilder;
		}

		public Authentication authenticate(Authentication authentication)
				throws AuthenticationException {
			if (delegate != null) {
				// 如果被代理的 AuthenticationManager delegate 已经被构建则直接使用它进行认证
				return delegate.authenticate(authentication);
			}

			synchronized (delegateMonitor) {
				if (delegate == null) {
					// 如果被代理的 AuthenticationManager delegate 尚未被构建，则在本次认证调用
					// 中先对其进行构建，构建成功后忘掉所用的delegateBuilder
					// 该模式中，这次认证也是对被代理的目标 AuthenticationManager 的首次认证调用
					delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}
			// 对目标 AuthenticationManager 的首次认证调用
			return delegate.authenticate(authentication);
		}
		// 从指定应用上下文及其祖先上下文中查找类型为  AuthenticationManager 的 bean 的名称，可能有多个

		private static Set<String> getAuthenticationManagerBeanNames(
				ApplicationContext applicationContext) {
			String[] beanNamesForType = BeanFactoryUtils
					.beanNamesForTypeIncludingAncestors(applicationContext,
							AuthenticationManager.class);
			return new HashSet<>(Arrays.asList(beanNamesForType));
		}

		// 确保没有循环依赖
		private static void validateBeanCycle(Object auth, Set<String> beanNames) {
			if (auth != null && !beanNames.isEmpty()) {
				if (auth instanceof Advised) {
					Advised advised = (Advised) auth;
					TargetSource targetSource = advised.getTargetSource();
					if (targetSource instanceof LazyInitTargetSource) {
						LazyInitTargetSource lits = (LazyInitTargetSource) targetSource;
						if (beanNames.contains(lits.getTargetBeanName())) {
							throw new FatalBeanException(
									"A dependency cycle was detected when trying to resolve the AuthenticationManager. Please ensure you have configured authentication.");
						}
					}
				}
				beanNames = Collections.emptySet();
			}
		}
	}

	/**
	 * 内部AuthenticationManagerBuilder
	 */
	static class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {
		private PasswordEncoder defaultPasswordEncoder;

		/**
		 * Creates a new instance
		 *
		 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder(
				ObjectPostProcessor<Object> objectPostProcessor, PasswordEncoder defaultPasswordEncoder) {
			super(objectPostProcessor);
			this.defaultPasswordEncoder = defaultPasswordEncoder;
		}

		/**
		 * 添加基于内存身份认证到AuthenticationManagerBuilder实例中，并返回InMemoryUserDetailsManagerConfigurer允许自定义内存认证
		 *
		 * @return
		 * @throws Exception
		 */
		@Override
		public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
				throws Exception {
			return super.inMemoryAuthentication()
					.passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication()
				throws Exception {
			return super.jdbcAuthentication()
					.passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
				T userDetailsService) throws Exception {
			return super.userDetailsService(userDetailsService)
					.passwordEncoder(this.defaultPasswordEncoder);
		}
	}

	/**
	 * 内部实现类
	 * // 内部嵌套类，延迟口令/密码加密器，将对口令/密码加密器对象的获取延迟到对其进行首次调用时
	 */
	static class LazyPasswordEncoder implements PasswordEncoder {
		//应用上下文
		private ApplicationContext applicationContext;
		//用于编码密码的服务接口
		private PasswordEncoder passwordEncoder;

		LazyPasswordEncoder(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		public String encode(CharSequence rawPassword) {
			return getPasswordEncoder().encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword,
				String encodedPassword) {
			return getPasswordEncoder().matches(rawPassword, encodedPassword);
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			return getPasswordEncoder().upgradeEncoding(encodedPassword);
		}

		/**
		 * // 获取最终干活的PasswordEncoder
		 *
		 * @return
		 */
		private PasswordEncoder getPasswordEncoder() {
			if (this.passwordEncoder != null) {
				return this.passwordEncoder;
			}
			//获取PasswordEncoder实例
			PasswordEncoder passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			if (passwordEncoder == null) {
				//工厂类创建PasswordEncoder
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		// 从Spring IoC容器中获取Bean 有可能获取不到
		private <T> T getBeanOrNull(Class<T> type) {
			try {
				return this.applicationContext.getBean(type);
			} catch (NoSuchBeanDefinitionException notFound) {
				return null;
			}
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}
	}
}
