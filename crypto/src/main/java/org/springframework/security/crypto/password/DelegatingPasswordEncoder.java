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

package org.springframework.security.crypto.password;

import java.util.HashMap;
import java.util.Map;

/**
 * 该类为一个委托类
 * DelegatingPasswordEncoder 也是实现了 PasswordEncoder 接口，所以它里边的核心方法也是两个：encode 方法用来对密码进行编码，matches 方法用来校验密码。
 * 在 DelegatingPasswordEncoder 的构造方法中，通过 通过传入的两个参数 encodingId 和 encoders ，获取到默认的编码器赋值给 passwordEncoderForEncode，默认的编码器实际上就是 BCryptPasswordEncoder。
 * 在 encode 方法中对密码进行编码，但是编码的方式加了前缀，前缀是 {编码器名称} ，例如如果你使用 BCryptPasswordEncoder 进行编码，那么生成的密码就类似 {bcrypt}$2a$10$oE39aG10kB/rFu2vQeCJTu/V/v4n6DRR0f8WyXRiAYvBpmadoOBE.。这样有什么用呢？每种密码加密之后，都会加上一个前缀，这样看到前缀，就知道该密文是使用哪个编码器生成的了。
 * 最后 matches 方法的逻辑就很清晰了，先从密文中提取出来前缀，再根据前缀找到对应的 PasswordEncoder，然后再调用 PasswordEncoder 的 matches 方法进行密码比对。
 * 如果根据提取出来的前缀，找不到对应的 PasswordEncoder，那么就会调用 UnmappedIdPasswordEncoder#matches 方法，进行密码比对，该方法实际上并不会进行密码比对，而是直接抛出异常。
 * <p>
 * <p>
 * https://felord.cn/spring-security-crypt.html
 * <p>
 * 一种密码编码器，根据前缀标识符委托给另一个密码编码器。
 * <p>
 * A password encoder that delegates to another PasswordEncoder based upon a prefixed
 * identifier.
 *
 * <h2>Constructing an instance</h2>
 * <p>
 * You can easily construct an instance using
 * {@link org.springframework.security.crypto.factory.PasswordEncoderFactories}.
 * Alternatively, you may create your own custom instance. For example:
 *
 * <pre>
 * String idForEncode = "bcrypt";
 * Map<String,PasswordEncoder> encoders = new HashMap<>();
 * encoders.put(idForEncode, new BCryptPasswordEncoder());
 * encoders.put("noop", NoOpPasswordEncoder.getInstance());
 * encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
 * encoders.put("scrypt", new SCryptPasswordEncoder());
 * encoders.put("sha256", new StandardPasswordEncoder());
 *
 * PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(idForEncode, encoders);
 * </pre>
 * <p>
 * 密码存储格式如下：
 * id查找PasswordEncoder
 * <h2>Password Storage Format</h2>
 * <p>
 * The general format for a password is:
 *
 * <pre>
 * {id}encodedPassword
 * </pre>
 * <p>
 * Such that "id" is an identifier used to look up which {@link PasswordEncoder} should
 * be used and "encodedPassword" is the original encoded password for the selected
 * {@link PasswordEncoder}. The "id" must be at the beginning of the password, start with
 * "{" and end with "}". If the "id" cannot be found, the "id" will be null.
 * <p>
 * For example, the following might be a list of passwords encoded using different "id".
 * All of the original passwords are "password".
 *
 * <pre>
 * {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
 * {noop}password
 * {pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc
 * {scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=
 * {sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0
 * </pre>
 * <p>
 * For the DelegatingPasswordEncoder that we constructed above:
 *
 * <ol>
 * <li>The first password would have a {@code PasswordEncoder} id of "bcrypt" and
 * encodedPassword of "$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG".
 * When matching it would delegate to
 * {@link org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder}</li>
 * <li>The second password would have a {@code PasswordEncoder} id of "noop" and
 * encodedPassword of "password". When matching it would delegate to
 * {@link NoOpPasswordEncoder}</li>
 * <li>The third password would have a {@code PasswordEncoder} id of "pbkdf2" and
 * encodedPassword of
 * "5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc".
 * When matching it would delegate to {@link Pbkdf2PasswordEncoder}</li>
 * <li>The fourth password would have a {@code PasswordEncoder} id of "scrypt" and
 * encodedPassword of
 * "$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc="
 * When matching it would delegate to
 * {@link org.springframework.security.crypto.scrypt.SCryptPasswordEncoder}</li>
 * <li>The final password would have a {@code PasswordEncoder} id of "sha256" and
 * encodedPassword of
 * "97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0".
 * When matching it would delegate to {@link StandardPasswordEncoder}</li>
 * </ol>
 *
 * <h2>Password Encoding</h2>
 * <p>
 * The {@code idForEncode} passed into the constructor determines which
 * {@link PasswordEncoder} will be used for encoding passwords. In the
 * {@code DelegatingPasswordEncoder} we constructed above, that means that the result of
 * encoding "password" would be delegated to {@code BCryptPasswordEncoder} and be prefixed
 * with "{bcrypt}". The end result would look like:
 *
 * <pre>
 * {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
 * </pre>
 *
 * <h2>Password Matching</h2>
 * <p>
 * Matching is done based upon the "id" and the mapping of the "id" to the
 * {@link PasswordEncoder} provided in the constructor. Our example in "Password Storage
 * Format" provides a working example of how this is done.
 * <p>
 * By default the result of invoking {@link #matches(CharSequence, String)} with a
 * password with an "id" that is not mapped (including a null id) will result in an
 * {@link IllegalArgumentException}. This behavior can be customized using
 * {@link #setDefaultPasswordEncoderForMatches(PasswordEncoder)}.
 *
 * @author Rob Winch
 * @author Michael Simons
 * @see org.springframework.security.crypto.factory.PasswordEncoderFactories
 * @since 5.0
 */
public class DelegatingPasswordEncoder implements PasswordEncoder {
	private static final String PREFIX = "{";
	private static final String SUFFIX = "}";
	//通过id来匹配编码器，该id不能是{} 包括的。
	private final String idForEncode;
	//通过上面idForEncode所匹配到的PasswordEncoder 用来对密码进行编码。
	private final PasswordEncoder passwordEncoderForEncode;
	//用来维护多个idForEncode与具体PasswordEncoder的映射关系。DelegatingPasswordEncoder 初始化时装载进去，会在初始化时进行一些规则校验。
	//如 noop对应的为NoOpPasswordEncoder
	private final Map<String, PasswordEncoder> idToPasswordEncoder;
	//默认的密码匹配器，上面的Map中都不存在就用它来执行matches方法进行匹配验证。这是一个内部类实现。
	private PasswordEncoder defaultPasswordEncoderForMatches = new UnmappedIdPasswordEncoder();

	/**
	 * 创建一个实例
	 * Creates a new instance
	 *
	 * @param idForEncode         the id used to lookup which {@link PasswordEncoder} should be
	 *                            used for {@link #encode(CharSequence)}
	 * @param idToPasswordEncoder a Map of id to {@link PasswordEncoder} used to determine
	 *                            which {@link PasswordEncoder} should be used for {@link #matches(CharSequence, String)}
	 */
	public DelegatingPasswordEncoder(String idForEncode,
			Map<String, PasswordEncoder> idToPasswordEncoder) {
		if (idForEncode == null) {
			throw new IllegalArgumentException("idForEncode cannot be null");
		}
		if (!idToPasswordEncoder.containsKey(idForEncode)) {
			throw new IllegalArgumentException("idForEncode " + idForEncode + "is not found in idToPasswordEncoder " + idToPasswordEncoder);
		}
		//循环遍历，并将密码保存
		for (String id : idToPasswordEncoder.keySet()) {
			if (id == null) {
				continue;
			}
			if (id.contains(PREFIX)) {
				throw new IllegalArgumentException("id " + id + " cannot contain " + PREFIX);
			}
			if (id.contains(SUFFIX)) {
				throw new IllegalArgumentException("id " + id + " cannot contain " + SUFFIX);
			}
		}
		this.idForEncode = idForEncode;
		this.passwordEncoderForEncode = idToPasswordEncoder.get(idForEncode);
		this.idToPasswordEncoder = new HashMap<>(idToPasswordEncoder);
	}

	/**
	 * 设置默认的密码匹配器
	 * Sets the {@link PasswordEncoder} to delegate to for
	 * {@link #matches(CharSequence, String)} if the id is not mapped to a
	 * {@link PasswordEncoder}.
	 *
	 * <p>
	 * The encodedPassword provided will be the full password
	 * passed in including the {"id"} portion.* For example, if the password of
	 * "{notmapped}foobar" was used, the "id" would be "notmapped" and the encodedPassword
	 * passed into the {@link PasswordEncoder} would be "{notmapped}foobar".
	 * </p>
	 *
	 * @param defaultPasswordEncoderForMatches the encoder to use. The default is to
	 *                                         throw an {@link IllegalArgumentException}
	 */
	public void setDefaultPasswordEncoderForMatches(
			PasswordEncoder defaultPasswordEncoderForMatches) {
		if (defaultPasswordEncoderForMatches == null) {
			throw new IllegalArgumentException("defaultPasswordEncoderForMatches cannot be null");
		}
		this.defaultPasswordEncoderForMatches = defaultPasswordEncoderForMatches;
	}


	/**
	 * 从上面源码可以看出来通过DelegatingPasswordEncoder 编码后的密码是遵循一定的规则的，遵循{idForEncode}encodePassword 。也就是前缀{} 包含了编码的方式再拼接上该方式编码后的密码串。
	 *
	 * @param rawPassword
	 * @return
	 */
	@Override
	public String encode(CharSequence rawPassword) {
		return PREFIX + this.idForEncode + SUFFIX + this.passwordEncoderForEncode.encode(rawPassword);
	}

	/**
	 * 密码匹配通过传入原始密码和遵循{idForEncode}encodePassword规则的密码编码串。通过获取编码方式id (idForEncode) 来从 DelegatingPasswordEncoder中的映射集合idToPasswordEncoder中获取具体的PasswordEncoder进行匹配校验。
	 * 找不到就使用UnmappedIdPasswordEncoder 。
	 *
	 * @param rawPassword           the raw password to encode and match
	 * @param prefixEncodedPassword
	 * @return
	 */
	@Override
	public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {

		if (rawPassword == null && prefixEncodedPassword == null) {
			return true;
		}
		//去掉{}符合
		String id = extractId(prefixEncodedPassword);
		//从map中获取密码匹配器
		PasswordEncoder delegate = this.idToPasswordEncoder.get(id);
		if (delegate == null) {
			return this.defaultPasswordEncoderForMatches
					.matches(rawPassword, prefixEncodedPassword);
		}
		//获取密码
		String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
		return delegate.matches(rawPassword, encodedPassword);
	}

	/**
	 * 去掉前缀和后缀 如{},获取真正的密码的ID,
	 *
	 * @param prefixEncodedPassword
	 * @return
	 */
	private String extractId(String prefixEncodedPassword) {
		if (prefixEncodedPassword == null) {
			return null;
		}
		int start = prefixEncodedPassword.indexOf(PREFIX);
		if (start != 0) {
			return null;
		}
		int end = prefixEncodedPassword.indexOf(SUFFIX, start);
		if (end < 0) {
			return null;
		}
		return prefixEncodedPassword.substring(start + 1, end);
	}

	/**
	 * 是否需要对编码后的密码再次进行编码,默认为false
	 *
	 * @param prefixEncodedPassword
	 * @return
	 */
	@Override
	public boolean upgradeEncoding(String prefixEncodedPassword) {
		String id = extractId(prefixEncodedPassword);
		if (!this.idForEncode.equalsIgnoreCase(id)) {
			return true;
		} else {
			String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
			return this.idToPasswordEncoder.get(id).upgradeEncoding(encodedPassword);
		}
	}

	/**
	 * 获取真正的密码
	 *
	 * @param prefixEncodedPassword
	 * @return
	 */
	private String extractEncodedPassword(String prefixEncodedPassword) {
		int start = prefixEncodedPassword.indexOf(SUFFIX);
		return prefixEncodedPassword.substring(start + 1);
	}

	/**
	 * 当上面的map都不存在的情况下，用其进行匹配密码
	 * Default {@link PasswordEncoder} that throws an exception that a id could
	 */
	private class UnmappedIdPasswordEncoder implements PasswordEncoder {

		@Override
		public String encode(CharSequence rawPassword) {
			throw new UnsupportedOperationException("encode is not supported");
		}

		@Override
		public boolean matches(CharSequence rawPassword,
				String prefixEncodedPassword) {
			String id = extractId(prefixEncodedPassword);
			throw new IllegalArgumentException("There is no PasswordEncoder mapped for the id \"" + id + "\"");
		}
	}
}
