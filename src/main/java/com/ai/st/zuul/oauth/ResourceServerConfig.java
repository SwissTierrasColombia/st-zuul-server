package com.ai.st.zuul.oauth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Value("${oauth.jwt.key}")
	private String jwtKey;

	public static final String ROLE_ADMINISTRATOR = "ADMINISTRADOR";
	public static final String ROLE_MANAGER = "GESTOR";
	public static final String ROLE_OPERATOR = "OPERADOR";
	public static final String ROLE_SUPPLY_SUPPLIER = "PROVEEDOR_INSUMO";

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore());
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()

				// microservice oauth
				.antMatchers("/api/security/oauth/**").permitAll()

				// microservice ili
				.antMatchers("/api/ili/ili2pg/v1/schema-import").authenticated()
				.antMatchers("/api/ili/ilivalidator/v1/validate").authenticated()
				.antMatchers("/api/ili/ilivalidator/v1/validate/background").authenticated()
				.antMatchers("/api/ili/ili2pg/v1/import").authenticated()
				.antMatchers("/api/ili/ili2pg/v1/integration/cadastre-registration").authenticated()
				.antMatchers("/api/ili/ili2pg/v1/integration/cadastre-registration-reference").authenticated()
				.antMatchers("/api/ili/ili2pg/v1/export").authenticated()
				.antMatchers(HttpMethod.GET, "/api/ili/versions/v1/versions").authenticated()

				// microservice managers
				.antMatchers(HttpMethod.GET, "/api/managers/v1/managers").hasRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/managers/v1/managers/{managerId}").hasRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/managers/v1/profiles").hasRole(ROLE_ADMINISTRATOR)
				
				// microservice workspaces
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/departments").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/departments/{departmentId}/municipalities").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces").hasRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/municipalities/{municipalityId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces/{workspaceId}/operators").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces/{workspaceId}/operators/deliveries").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/operators/deliveries").hasRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/workspaces/{workspaceId}").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/{workspaceId}/supports").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/{workspaceId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/{workspaceId}/operators").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/municipalities/{municipalityId}/active").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces/integration/{municipalityId}").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/{workspaceId}/integrations").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces/{workspaceId}/integrations/{integrationId}").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces/{workspaceId}/integrations/{integrationId}/export").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.DELETE, "/api/workspaces/v1/workspaces/{workspaceId}/integrations/{integrationId}").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/download-supply/{supplyId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.DELETE, "/api/workspaces/v1/workspaces/{workspaceId}/supplies/{supplyId}").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/requests/{requestId}").hasAnyRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/requests/{requestId}/close").hasAnyRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/municipalities/{municipalityId}/requests").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/pending-requests").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/requests/emmiters").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/administration/users").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/administration/users/reset-password").authenticated()
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/supplies/{municipalityId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/tasks/{taskId}/start").authenticated()
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/tasks/{taskId}/cancel").authenticated()
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/tasks/{taskId}/finish").authenticated()
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/tasks/pending").authenticated()
				
				// microservice operators
				.antMatchers(HttpMethod.GET, "/api/operators/v1/operators").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/operators/v1/operators/{operatorId}").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				
				// microservice providers
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/providers").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/providers/{providerId}/types-supplies").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/providers/{providerId}/profiles").hasAnyRole(ROLE_ADMINISTRATOR)
				
				// microservice admininistrator
				.antMatchers(HttpMethod.GET, "/api/administration/v1/users").hasAnyRole(ROLE_ADMINISTRATOR)
				
				// microservice filemanager
				.antMatchers(HttpMethod.POST, "/api/filemanager/v1/file").permitAll()
				
				// others services
				.anyRequest().denyAll().and().cors().configurationSource(corsConfigurationSource());
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {

		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedOrigins(Arrays.asList("*"));
		corsConfig.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Access-Control-Allow-Origin"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);

		return source;
	}

	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter() {

		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(
				new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);

		return bean;
	}

	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setSigningKey(jwtKey);
		return tokenConverter;
	}

}
