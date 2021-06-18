/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.List;
import java.util.Map;
import javax.servlet.Filter;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.crypto.RsaKeyConversionServicePostProcessor;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;


/**
 * https://blog.csdn.net/sanjun333/article/details/111611985
 * 简单的说，这个类的作用就是用来创建FilterChainProxy，FilterChainProxy是一个Servlet Filter，他是一组SecurityFilterChain的代理，用于管理这些SecurityFilterChain
 * <p>
 * 首先，FilterChainProxy是SpringSecurity提供的基于Servlet标准的过滤器，他可以被Servlet容器使用。SecurityFilterChain是SpringSecurity提供的自有安全过滤器链，他不是基于Servlet标准的过滤器。
 * SpringSecurity使用FilterChainProxy管理一组SecurityFilterChain，这样就可以通过代理的方式将SpringSecurity自有的滤器链应用于Servlet容器。
 * <p>
 * 然后，当前配置类会加载容器中所有的WebSecurityConfigurer配置类、WebSecurityCustomizer配置类（5.4以后）、SecurityFilterChain过滤器链。这些都是用于配置生成一个WebSecurity。
 * <p>
 * 接着，当WebSecurity实例被构建完成后，会使用WebSecurity去创建一个FilterChainProxy，这个FilterChainProxy会被放到容器中
 * <p>
 * <p>
 * https://felord.cn/spring-security-autoconfigure.html
 * 该配置类WebSecurityConfiguration使用一个WebSecurity对象基于用户指定的或者默认的安全配置，你可以通过继承 WebSecurityConfigurerAdapter 或者实现 WebSecurityConfigurer 来定制 WebSecurity
 * 创建一个FilterChainProxy Bean来对用户请求进行安全过滤。这个FilterChainProxy的名称就是 WebSecurityEnablerConfiguration上的 BeanIds.SPRING_SECURITY_FILTER_CHAIN 也就是 springSecurityFilterChain,它是一个Filter，
 * 最终会被作为Servlet过滤器链中的一个Filter应用到Servlet容器中。安全处理的策略主要是过滤器的调用顺序。WebSecurityConfiguration 最终会通过 @EnableWebSecurity 应用到系统。
 * <p>
 * Spring Web Security 的配置类 :
 * 1. 使用一个 WebSecurity 对象基于安全配置创建一个 FilterChainProxy 对象来对用户请求进行安全过滤。
 * 2. 也会暴露诸如 安全SpEL表达式处理器 SecurityExpressionHandler 等一些类。
 * <p>
 * Uses a {@link WebSecurity} to create the {@link FilterChainProxy} that performs the web
 * based security for Spring Security. It then exports the necessary beans. Customizations
 * can be made to {@link WebSecurity} by extending {@link WebSecurityConfigurerAdapter}
 * and exposing it as a {@link Configuration} or implementing
 * {@link WebSecurityConfigurer} and exposing it as a {@link Configuration}. This
 * configuration is imported when using {@link EnableWebSecurity}.
 *
 * @author Rob Winch
 * @author Keesun Baik
 * @see EnableWebSecurity
 * @see WebSecurity
 * @since 3.2
 */
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {
	//SpringSecurity的FilterChainProxy的建造器
	private WebSecurity webSecurity;
	//标识是否开启debug模式，来自注解@EnableWebSecurity的属性debug,默认为false
	private Boolean debugEnabled;
	//SpringSecurity的配置类列表
	private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;
	//一个类加载器
	private ClassLoader beanClassLoader;
	//对象后处理器（这里依赖注入的是AutowireBeanFactoryObjectPostProcessor）
	@Autowired(required = false)
	private ObjectPostProcessor<Object> objectObjectPostProcessor;

	//代理监听器 应该时监听 DefaultAuthenticationEventPublisher 的一些处理策略
	@Bean
	public static DelegatingApplicationListener delegatingApplicationListener() {
		return new DelegatingApplicationListener();
	}

	/**
	 * 安全SpEL表达式处理器 SecurityExpressionHandler 缺省为一个 DefaultWebSecurityExpressionHandler
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
		return webSecurity.getExpressionHandler();
	}

	/**
	 * 创建FilterChainProxy代理
	 * Creates the Spring Security Filter Chain
	 * 接着会调用springSecurityFilterChain()方法，这个方法会判断我们上一个方法中有没有获取到webSecurityConfigurers，没有的话这边会创建一个WebSecurityConfigurerAdapter实例，
	 * 并追加到websecurity中。接着调用websecurity的build方法。实际调用的是websecurity的父类AbstractSecurityBuilder的build方法
	 * <p>
	 * 首先，在这个方法中首先会判断是否有用户自定义的WebSecurityConfigurer和SecurityFilterChain：
	 * <p>
	 * 如果这两种自定义实例同时存在则会抛出异常。
	 * 如果只存在SecurityFilterChains，将其设置到已经被创建的webSecurity中。
	 * 如果这两个自定义实例都不存在，则会创建一个默认的WebSecurityConfigurerAdapter配置，并将其设置到已经被创建的webSecurity中。
	 *
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		/**
		 * 1、判断是否有自定义配置类
		 */
		boolean hasConfigurers = webSecurityConfigurers != null
				&& !webSecurityConfigurers.isEmpty();
		/**
		 * 4、如果没有配置类且没有SecurityFilterChain，创建一个默认配置，并添加到webSecurity
		 *
		 */
		//这里的意思是我们是否有自定义配置其实就是是否有注入WebSecurityConfigurer的子类，没有的话，我默认的创建一个默认的，但是默认的我们自己不可修改
		if (!hasConfigurers) {
			WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			webSecurity.apply(adapter);
		}
		/**
		 * 7、以上配置完成webSecurity后调用WebSecurity.build()方法创建FilterChainProxy
		 */
		//我们可以知道，到此为止，已经建立了一个Filter对象，而这个Filter将会拦截掉我们的请求，对请求进行过滤拦截，从而起到对资源进行认证保护的作用。然后这个Filter并非我们自己平时定义的Filter这么简单,
		// 这个过滤器也只是一个代理的过滤器而已，里面还会有过滤器链
		//
		//作者：怪诞140819
		//链接：https://www.jianshu.com/p/0c54788c94f3
		//来源：简书
		//著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
		//webSecurity对象在此时已经加载完所有的配置
		//webSecurity对象为我们创建一个Filter通过的是build()方法
		return webSecurity.build();
	}

	/**
	 * 用于模板 如JSP Freemarker 的一些页面标签按钮控制支持
	 * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary for the JSP
	 * tag support.
	 *
	 * @return the {@link WebInvocationPrivilegeEvaluator}
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public WebInvocationPrivilegeEvaluator privilegeEvaluator() {
		return webSecurity.getPrivilegeEvaluator();
	}

	/**
	 * 在这个方法中会创建一个WebSecurity实例，然后将注解参数列表中@Value()注解引入的所有WebSecurityConfigurer配置设置到WebSecurity实例中。
	 * 同时初始化了当前配置类的两个属性值webSecurity和webSecurityConfigurers。
	 * <p>
	 * * 获取并设置容器中已经加载的所有WebSecurityConfigurer实例用于配置，初始化一个WebSecurity
	 * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>}
	 * instances used to create the web configuration.
	 *
	 * @param objectPostProcessor    the {@link ObjectPostProcessor} used to create a
	 *                               {@link WebSecurity} instance 后处理对象（AutowireBeanFactoryObjectPostProcessor）
	 * @param webSecurityConfigurers the
	 *                               {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to
	 *                               create the web configuration 用户自定义的配置（WebSecurityConfigurerAdapter的子类或是WebSecurityConfigurer接口的实现）
	 * @throws Exception
	 */
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(
			ObjectPostProcessor<Object> objectPostProcessor,
			@Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}") List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers)
			throws Exception {
		//创建一个WebSecurity
		//初始化一个WebSecurity实例，并其赋值到类属性webSecurity上
		webSecurity = objectPostProcessor
				.postProcess(new WebSecurity(objectPostProcessor));
		/**
		 * 2、设置是否开启debug模式
		 */
		if (debugEnabled != null) {
			webSecurity.debug(debugEnabled);
		}
		/**
		 * 3、根据@Order注解排序，然后检测配置排序是否有重复
		 */
		webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE);

		Integer previousOrder = null;
		Object previousConfig = null;
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			//获取Order注解的值
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException(
						"@Order on WebSecurityConfigurers must be unique. Order of "
								+ order + " was already used on " + previousConfig + ", so it cannot be used on "
								+ config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}
		/**
		 * 4、将配置添加到webSecurity中
		 */
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			webSecurity.apply(webSecurityConfigurer);
		}
		/**
		 * 5、将配置类列表复制到类属性webSecurityConfigurers上
		 */
		this.webSecurityConfigurers = webSecurityConfigurers;
	}

	@Bean
	public static BeanFactoryPostProcessor conversionServicePostProcessor() {
		return new RsaKeyConversionServicePostProcessor();
	}

	@Bean
	public static AutowiredWebSecurityConfigurersIgnoreParents autowiredWebSecurityConfigurersIgnoreParents(
			ConfigurableListableBeanFactory beanFactory) {
		return new AutowiredWebSecurityConfigurersIgnoreParents(beanFactory);
	}

	/**
	 * 主要用来进行排序
	 * A custom verision of the Spring provided AnnotationAwareOrderComparator that uses
	 * {@link AnnotationUtils#findAnnotation(Class, Class)} to look on super class
	 * instances for the {@link Order} annotation.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static class AnnotationAwareOrderComparator extends OrderComparator {
		private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

		@Override
		protected int getOrder(Object obj) {
			return lookupOrder(obj);
		}

		/**
		 * 获取Order注解的值
		 *
		 * @param obj
		 * @return
		 */
		private static int lookupOrder(Object obj) {
			if (obj instanceof Ordered) {
				return ((Ordered) obj).getOrder();
			}
			if (obj != null) {
				Class<?> clazz = (obj instanceof Class ? (Class<?>) obj : obj.getClass());
				Order order = AnnotationUtils.findAnnotation(clazz, Order.class);
				if (order != null) {
					return order.value();
				}
			}
			return Ordered.LOWEST_PRECEDENCE;
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.context.annotation.ImportAware#setImportMetadata(org.
	 * springframework.core.type.AnnotationMetadata)
	 */
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> enableWebSecurityAttrMap = importMetadata
				.getAnnotationAttributes(EnableWebSecurity.class.getName());
		AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes
				.fromMap(enableWebSecurityAttrMap);
		debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
		if (webSecurity != null) {
			webSecurity.debug(debugEnabled);
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.beans.factory.BeanClassLoaderAware#setBeanClassLoader(java.
	 * lang.ClassLoader)
	 */
	public void setBeanClassLoader(ClassLoader classLoader) {
		this.beanClassLoader = classLoader;
	}
}
