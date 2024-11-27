# directory-traversal
Introduce the incorrect access control vulnerabilities in White-Jotter project.

White-Jotter,a simple CMS developed by Spring Boot and Vue.js with development tutorials
# version
White-Jotter project

# Vulnerability causes
The main function of [URLPathMatchingFilter.java](https://github.com/Antabot/White-Jotter/blob/master/wj/src/main/java/com/gm/wj/filter/URLPathMatchingFilter.java) to implement permission control is in the onPreHandle function.


    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        if (HttpMethod.OPTIONS.toString().equals((httpServletRequest).getMethod())) {
            httpServletResponse.setStatus(HttpStatus.NO_CONTENT.value());
            return true;
        }

        if (null == adminPermissionService) {
            adminPermissionService = SpringContextUtils.getContext().getBean(AdminPermissionService.class);
        }

        String requestAPI = getPathWithinApplication(request);

        Subject subject = SecurityUtils.getSubject();

        if (!subject.isAuthenticated()) {
            log.info("未登录用户尝试访问需要登录的接口");
            return false;
        }

        // 判断访问接口是否需要过滤（数据库中是否有对应信息）
        boolean needFilter = adminPermissionService.needFilter(requestAPI);
        if (!needFilter) {
            return true;
        } else {
            // 判断当前用户是否有相应权限
            boolean hasPermission = false;
            String username = subject.getPrincipal().toString();
            Set<String> permissionAPIs = adminPermissionService.listPermissionURLsByUser(username);
            for (String api : permissionAPIs) {
                // 匹配前缀
                if (requestAPI.startsWith(api)) {
                    hasPermission = true;
                    break;
                }
            }

            if (hasPermission) {
                log.trace("用户：" + username + "访问了：" + requestAPI + "接口");
                return true;
            } else {
                log.warn( "用户：" + username + "访问了没有权限的接口：" + requestAPI);
                return false;
            }
        }
    }
   The function directly obtains the request path through getPathWithinApplication(request), which internally uses the unsafe method getRequestURI. This method does not process directory operations such as ./ and ../. It then uses the startsWith function to match the whitelist and determine whether the request requires permission validation.
   
   Because it use startsWith to match requests that contain the specified string or start with the specified string. If the match is successful, it returns true and will not perform identity verification.

  We can use directory traversal to bypass identity verification.When we access api/aaa/;/../admin/content/article as a user, we can directly access the api/admin/content/article, which is intended for admin only.

# Vulnerability reproduce

First, we find an interface that requires authentication to access, admin/content/article. This API is used to view the article content.

Then, we tried to access this endpoint by Postman without authentication information. We can see that due to the lack of authentication information, there is no results returned.
![Image Description](https://user-images.githubusercontent.com/your-username/your-image.png)




   
