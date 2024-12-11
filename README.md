# directory-traversal
Introduce the incorrect access control vulnerabilities in White-Jotter project.

White-Jotter,a simple CMS developed by Spring Boot and Vue.js with development tutorials
# version
White-Jotter project

# Vulnerability causes
The main function of https://github.com/Antabot/White-Jotter/blob/master/wj/src/main/java/com/gm/wj/config/ShiroConfiguration.java is use to configure the filter matching and authentication rules.


      public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/nowhere");

        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        Map<String, Filter> customizedFilter = new HashMap<>();  // 自定义过滤器设置 1

        customizedFilter.put("url", getURLPathMatchingFilter()); // 自定义过滤器设置 2，命名，需在设置过滤路径前

        filterChainDefinitionMap.put("/api/authentication", "authc"); // 防鸡贼登录
        filterChainDefinitionMap.put("/api/menu", "authc");
        filterChainDefinitionMap.put("/api/admin/**", "authc");

        filterChainDefinitionMap.put("/api/admin/**", "url");  // 自定义过滤器设置 3，设置过滤路径

        shiroFilterFactoryBean.setFilters(customizedFilter); // 自定义过滤器设置 4，启用
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }
  This code configures a Shiro security filter, where a custom filter is set up for specific API paths.It defines the filter's matching rules. However, it only matches certain API paths, meaning other paths will not be processed by the filter for authentication and related operations.

  If you manipulate the path with ./ or ../ (relative path references), it could potentially bypass the filter and directly access the controller layer, as the filter is only applied to specific API paths defined in the configuration.
  
  We can use directory traversal to bypass identity verification.When we access api/aaa/;/../admin/content/article as a user, we can directly access the api/admin/content/article, which is intended for admin only.

# Vulnerability reproduce

First, we find an interface that requires authentication to access, admin/content/article. This API is used to uploud the article content.

Then, we tried to access this endpoint by Postman without authentication information. We can see that due to the lack of authentication information, there is no results returned.
![Image Description](https://github.com/Dengdeng857/directory-traversal/blob/main/image/99ce0b9feb3e948a34bf857830a3b54.png)
![Image Description](https://github.com/Dengdeng857/directory-traversal/blob/main/image/1.jpg)
After that, also without authentication information, we try to access the /login/../export interface. We can see that the access is successful.

![Image Description](https://github.com/Dengdeng857/directory-traversal/blob/main/image/b52ee4200728bbdb7e0a0d258d0aef9.png)

# Impact
Users can use directory traversal to gain unauthorized access to the interface.


   
