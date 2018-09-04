package cn.zifangsky.controller;

import cn.zifangsky.common.Constants;
import cn.zifangsky.model.AuthorizationResponse;
import cn.zifangsky.model.BaiduUser;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.text.MessageFormat;

/**
 * 登录
 * @author zifangsky
 * @date 2018/7/9
 * @since 1.0.0
 */
@Controller
public class LoginController {

    @Autowired
    private RestTemplate restTemplate;

    @Value("${baidu.oauth2.client-id}")
    private String clientId;

    @Value("${baidu.oauth2.scope}")
    private String scope;

    @Value("${baidu.oauth2.client-secret}")
    private String clientSecret;

    @Value("${baidu.oauth2.user-authorization-uri}")
    private String authorizationUri;

    @Value("${baidu.oauth2.access-token-uri}")
    private String accessTokenUri;

    @Value("${baidu.oauth2.resource.userInfoUri}")
    private String userInfoUri;

    /**
     * 登录验证（实际登录调用认证服务器）
     * @author zifangsky
     * @date 2018/7/25 16:42
     * @since 1.0.0
     * @param request HttpServletRequest
     * @return org.springframework.web.servlet.ModelAndView
     */
    @RequestMapping("/login")
    public ModelAndView login(HttpServletRequest request){
        //当前系统登录成功之后的回调URL
        String redirectUrl = request.getParameter("redirectUrl");
        //当前系统请求认证服务器成功之后返回的Authorization Code
        String code = request.getParameter("code");

        //最后重定向的URL
        String resultUrl = "redirect:";
        HttpSession session = request.getSession();
        //当前请求路径
        String currentUrl = request.getRequestURL().toString();

        //code为空，则说明当前请求不是认证服务器的回调请求，则重定向URL到百度OAuth2.0登录
        if(StringUtils.isBlank(code)){
            //如果存在回调URL，则将这个URL添加到session
            if(StringUtils.isNoneBlank(redirectUrl)){
                session.setAttribute("redirectUrl",redirectUrl);
            }

            resultUrl += authorizationUri + MessageFormat.format("?client_id={0}&response_type=code&scope=basic&display=popup&redirect_uri={1}"
            ,clientId,currentUrl);
        }else{
            //1. 通过Authorization Code获取Access Token
            AuthorizationResponse response = restTemplate.getForObject(accessTokenUri + "?client_id={1}&client_secret={2}&grant_type=authorization_code&code={3}&redirect_uri={4}"
                    ,AuthorizationResponse.class
                    , clientId, clientSecret, code,currentUrl);

            //2. 如果正常返回
            if(response != null && StringUtils.isNoneBlank(response.getAccess_token())){
                System.out.println(response);

                //2.1 将Access Token存到session
                session.setAttribute(Constants.SESSION_ACCESS_TOKEN,response.getAccess_token());

                //2.2 再次查询用户基础信息，并将用户ID存到session
                BaiduUser baiduUser = restTemplate.getForObject(userInfoUri + "?access_token={1}"
                        ,BaiduUser.class
                        ,response.getAccess_token());

                if(baiduUser != null &&  StringUtils.isNoneBlank(baiduUser.getUserid())){
                    System.out.println(baiduUser);

                    session.setAttribute(Constants.SESSION_USER_ID,baiduUser.getUserid());
                }
            }

            //3. 从session中获取回调URL，并返回
            redirectUrl = (String) session.getAttribute("redirectUrl");
            session.removeAttribute("redirectUrl");
            if(StringUtils.isNoneBlank(redirectUrl)){
                resultUrl += redirectUrl;
            }else{
                resultUrl += "/user/userIndex";
            }
        }

        return new ModelAndView(resultUrl);
    }

}
