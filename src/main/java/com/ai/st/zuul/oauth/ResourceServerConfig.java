package com.ai.st.zuul.oauth;

import java.util.Arrays;
import java.util.Collections;

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
	public static final String ROLE_SUPER_ADMINISTRATOR = "SUPER_ADMINISTRADOR";

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
				.antMatchers(HttpMethod.GET, "/api/ili/versions/v1/versions").authenticated()
				.antMatchers(HttpMethod.POST, "/api/ili/xtf2json/v1/ili2json").permitAll()
				.antMatchers(HttpMethod.POST, "/api/ili/xtf2json/v1/shp2json").permitAll()
				.antMatchers(HttpMethod.POST, "/api/ili/xtf2json/v1/gpkg2json").permitAll()
				.antMatchers(HttpMethod.POST, "/api/ili/xtf2json/v1/kml2json").permitAll()
				.antMatchers(HttpMethod.POST, "/api/ili/xtf2json/v1/supply2json").hasAnyRole(ROLE_OPERATOR, ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/ili/xtf2json/v1/download/{id}/{key}/{type}").hasAnyRole(ROLE_OPERATOR, ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER)

				// microservice managers
				.antMatchers(HttpMethod.GET, "/api/managers/v1/managers").hasRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/managers/v1/managers/{managerId}").hasRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/managers/v1/profiles").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/managers/v1/managers").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/managers/v1/managers").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/managers/v1/managers/{managerId}/enable").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/managers/v1/managers/{managerId}/disable").hasAnyRole(ROLE_ADMINISTRATOR)
				
				// microservice workspaces
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/departments").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/departments/{departmentId}/municipalities").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces").hasRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/municipalities/{municipalityId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces/{workspaceId}/operators").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/workspaces/{workspaceId}/operators/deliveries").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/operators").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/operators/deliveries").hasRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/operators/deliveries/closed").hasRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/workspaces/{workspaceId}").hasRole(ROLE_ADMINISTRATOR)
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
				.antMatchers(HttpMethod.DELETE, "/api/workspaces/v1/workspaces/{workspaceId}/supplies/{supplyId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/requests/{requestId}").hasAnyRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/requests/{requestId}/close").hasAnyRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/municipalities/{municipalityId}/requests").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/pending-requests").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/closed-requests").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/requests/emmiters").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/profiles").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/profiles").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/profiles/{profileId}").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.DELETE, "/api/workspaces/v1/providers/profiles/{profileId}").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/types-supplies").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/types-supplies").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/types-supplies/{typeSupplyId}").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.DELETE, "/api/workspaces/v1/providers/types-supplies/{typeSupplyId}").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/administration/users").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_SUPER_ADMINISTRATOR, ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/administration/users/{userId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_SUPER_ADMINISTRATOR, ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/administration/users/{userId}/enable").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_SUPER_ADMINISTRATOR, ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/administration/users/{userId}/disable").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_SUPER_ADMINISTRATOR, ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/administration/users").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_SUPER_ADMINISTRATOR, ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/administration/users/{userId}/profiles").hasAnyRole(ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.DELETE, "/api/workspaces/v1/administration/users/{userId}/profiles").hasAnyRole(ROLE_MANAGER, ROLE_SUPPLY_SUPPLIER, ROLE_OPERATOR)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/administration/users/reset-password").authenticated()
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/supplies/{municipalityId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/tasks/{taskId}/start").authenticated()
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/tasks/{taskId}/cancel").authenticated()
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/tasks/{taskId}/finish").authenticated()
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/tasks/pending").authenticated()
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/operators/deliveries/{deliveryId}/disable").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/operators/deliveries/{deliveryId}/reports-individual/{supplyId}").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/operators/deliveries/{deliveryId}/reports-total").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/{workspaceId}/download-support/{supportId}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/requests/municipality").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/requests/provider").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/requests/package").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/integrations/running").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/integrations/pending").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/supplies-review").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/supplies-review/{supplyRequestedId}/start").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/providers/supplies-review/{supplyRequestedId}/records").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/supplies-review/{supplyRequestedId}/update/{boundarySpaceId}").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/supplies-review/{supplyRequestedId}/close").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers/supplies-review/{supplyRequestedId}/skip").hasRole(ROLE_SUPPLY_SUPPLIER)
				// petitions module
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/petitions").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/petitions/manager").hasRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/petitions/provider/open").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/petitions/provider/close").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/petitions/{petitionId}/accept").hasRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/petitions/{petitionId}/reject").hasRole(ROLE_SUPPLY_SUPPLIER)
				// supplies module
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/supplies/{supplyId}/active").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/supplies/{supplyId}/inactive").hasAnyRole(ROLE_MANAGER)
				// cadastral authority module
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/cadastral-authority/supplies/{municipalityId}").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/cadastral-authority/report/{municipalityId}").hasAnyRole(ROLE_ADMINISTRATOR)
				// providers module
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/types-supplies/{typeSupplyId}/enable").hasAnyRole(ROLE_SUPPLY_SUPPLIER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers/types-supplies/{typeSupplyId}/disable").hasAnyRole(ROLE_SUPPLY_SUPPLIER)
				// municipalities module
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/municipalities/by-manager/{managerId}").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/municipalities/not-workspace/departments/{departmentId}").hasAnyRole(ROLE_ADMINISTRATOR)
				// workspaces module
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/location").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.DELETE, "/api/workspaces/v1/workspaces/unassign/{municipalityId}/managers/{managerCode}").hasAnyRole(ROLE_ADMINISTRATOR)
				// managers module
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/managers/deliveries").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/managers/deliveries/{deliveryId}").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v1/workspaces/report-delivery/{deliveryId}").hasAnyRole(ROLE_MANAGER)
				// integrations module
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/integrations/{integrationId}/configure-view").hasAnyRole(ROLE_MANAGER)

				// microservice operators
				.antMatchers(HttpMethod.GET, "/api/operators/v1/operators").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/operators/v1/operators/{operatorId}").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.POST, "/api/operators/v1/operators").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/operators/v1/operators").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/operators/v1/operators/{operatorId}/disable").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/operators/v1/operators/{operatorId}/enable").hasAnyRole(ROLE_ADMINISTRATOR)
				
				// microservice providers
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/providers").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.POST, "/api/providers-supplies/v1/providers").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/providers-supplies/v1/providers").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.DELETE, "/api/providers-supplies/v1/providers/{providerId}").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/providers/{providerId}/types-supplies").hasAnyRole(ROLE_MANAGER, ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/providers/{providerId}/profiles").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/categories").hasRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/providers-supplies/v1/providers/{providerId}/enable").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/providers-supplies/v1/providers/{providerId}/disable").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/providers-supplies/v1/providers/from-requested-manager/{managerId}").hasAnyRole(ROLE_MANAGER)
				
				.antMatchers(HttpMethod.POST, "/api/workspaces/v1/providers").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v1/providers").hasAnyRole(ROLE_ADMINISTRATOR)
				
				// microservice administrator
				.antMatchers(HttpMethod.GET, "/api/administration/v1/users").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/administration/v1/users/recover").permitAll()
				.antMatchers(HttpMethod.PUT, "/api/administration/v1/users/reset").permitAll()
				.antMatchers(HttpMethod.GET, "/api/administration/v1/users/managers").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/administration/v1/users/providers").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/administration/v1/users/operators").hasAnyRole(ROLE_ADMINISTRATOR)
				
				// microservice supplies
				.antMatchers(HttpMethod.GET, "/api/supplies/v1/attachments-types").hasAnyRole(ROLE_ADMINISTRATOR)

				// microservice quality
				.antMatchers(HttpMethod.POST, "/api/quality/v1/deliveries").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/quality/v1/deliveries").hasAnyRole(ROLE_OPERATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/quality/v1/deliveries/{deliveryId}").hasAnyRole(ROLE_OPERATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/quality/v1/deliveries/{deliveryId}").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.DELETE, "/api/quality/v1/deliveries/{deliveryId}").hasAnyRole(ROLE_OPERATOR)

				.antMatchers(HttpMethod.POST, "/api/quality/v1/deliveries/{deliveryId}/products").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/quality/v1/deliveries/{deliveryId}/products").hasAnyRole(ROLE_OPERATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/quality/v1/deliveries/{deliveryId}/products/{deliveryProductId}").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.DELETE, "/api/quality/v1/deliveries/{deliveryId}/products/{deliveryProductId}").hasAnyRole(ROLE_OPERATOR)

				.antMatchers(HttpMethod.POST, "/api/quality/v1/deliveries/{deliveryId}/products/{deliveryProductId}/attachments").hasAnyRole(ROLE_OPERATOR)
				.antMatchers(HttpMethod.GET, "/api/quality/v1/deliveries/{deliveryId}/products/{deliveryProductId}/attachments").hasAnyRole(ROLE_OPERATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/quality/v1/deliveries/{deliveryId}/products/{deliveryProductId}/attachments/{attachmentId}/download").hasAnyRole(ROLE_OPERATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.DELETE, "/api/quality/v1/deliveries/{deliveryId}/products/{deliveryProductId}/attachments/{attachmentId}").hasAnyRole(ROLE_OPERATOR)

				.antMatchers(HttpMethod.GET, "/api/quality/v1/products").hasAnyRole(ROLE_MANAGER, ROLE_OPERATOR)

				/*
				 * Services V2
				 */
				.antMatchers(HttpMethod.GET, "/api/workspaces/v2/municipalities/{managerCode}/not-belong/departments/{departmentId}").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v2/workspaces/validate-municipalities-to-assign").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.POST, "/api/workspaces/v2/workspaces/assign-manager").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v2/workspaces/{workspaceId}/download-support-manager/{managerCode}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v2/workspaces/{workspaceId}/managers/{managerCode}").hasAnyRole(ROLE_ADMINISTRATOR)
				.antMatchers(HttpMethod.PUT, "/api/workspaces/v2/workspaces/{workspaceId}/operators/{operatorCode}").hasAnyRole(ROLE_MANAGER)
				.antMatchers(HttpMethod.GET, "/api/workspaces/v2/workspaces/{workspaceId}/download-support-operator/{operatorCode}").hasAnyRole(ROLE_ADMINISTRATOR, ROLE_MANAGER)

				.antMatchers(HttpMethod.GET, "/api/supplies/v2/supplies/xtf/{municipalityCode}").hasAnyRole(ROLE_MANAGER)
				
				// others services
				.anyRequest().denyAll().and().cors().configurationSource(corsConfigurationSource());
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {

		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedOrigins(Collections.singletonList("*"));
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

