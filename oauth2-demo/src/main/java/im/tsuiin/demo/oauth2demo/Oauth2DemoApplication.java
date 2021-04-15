package im.tsuiin.demo.oauth2demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;


/**
 * @author ying
 */
@Configuration
@RestController
@RequestMapping("/dashboard")
@SpringBootApplication
@EnableOAuth2Client
public class Oauth2DemoApplication {

    @Value("${security.oauth2.resource.userInfoUri}")
    private String userInfoUri;


    public static void main(String[] args) {
        SpringApplication.run(Oauth2DemoApplication.class, args);
    }

    @RequestMapping("/message")
    public Map<String, Object> dashboard() {
        return Collections.singletonMap("message", "Yay!");
    }

    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

    @Controller
    public static class LoginErrors {

        @RequestMapping("/dashboard/login")
        public String dashboard() {
            return "redirect:/#/";
        }
    }

    @Component
    @EnableOAuth2Sso
    @Order(6)
    public static class LoginConfigurer extends WebSecurityConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/dashboard/**").authorizeRequests().anyRequest()
                    .authenticated().and().csrf()
                    .csrfTokenRepository(csrfTokenRepository()).and()
                    .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
                    .logout().logoutUrl("/dashboard/logout").permitAll()
                    .logoutSuccessUrl("/");
        }

        private Filter csrfHeaderFilter() {
            return new OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(HttpServletRequest request,
                                                HttpServletResponse response, FilterChain filterChain)
                        throws ServletException, IOException {
                    CsrfToken csrf = (CsrfToken) request
                            .getAttribute(CsrfToken.class.getName());
                    if (csrf != null) {
                        Cookie cookie = new Cookie("XSRF-TOKEN",
                                csrf.getToken());
                        cookie.setPath("/");
                        response.addCookie(cookie);
                    }
                    filterChain.doFilter(request, response);
                }
            };
        }

        private CsrfTokenRepository csrfTokenRepository() {
            HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
            repository.setHeaderName("X-XSRF-TOKEN");
            return repository;
        }
    }

    @Bean
    public AuthoritiesExtractor authoritiesExtractor() {
        return new AuthoritiesExtractor() {
            @Override
            public List<GrantedAuthority> extractAuthorities(final Map<String, Object> map) {
                OAuth2ProtectedResourceDetails details = new BaseOAuth2ProtectedResourceDetails();
                OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(details);

                System.err.println("userInfoUri: " + userInfoUri);
                System.err.println("template: " + oAuth2RestTemplate);
                System.err.println("MAP SIZE: " + map.size());
                Object userInfo = oAuth2RestTemplate.getForObject(userInfoUri, Object.class);
                System.err.println("userInfo: " + userInfo);
                for (Map.Entry<String, Object> entry : map.entrySet()) {
                    System.err.println(entry.getKey() + " = " + entry.getValue());
                }
                return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");
            }
        };
    }
}
