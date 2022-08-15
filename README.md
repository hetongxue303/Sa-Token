# Sa-Token

## 简介

官网：[Sa-Token](https://sa-token.dev33.cn/index.html)

sa-token是一个轻量级java权限认证框架，可以使鉴权变得更加优雅、简单！主要解决`登录认证`、`权限认证`、`单点登录`、`OAuth 2.0`
、`分布式session会话`、`微服务网关鉴权`等一系列权限问题！在使用API也是极为简单，只需要通过`StpUtil`即可实现。

---

## 基础使用

### 框架集成

#### 添加Sa-Token依赖

```xml
<!--sa-token-->
<dependency>
    <groupId>cn.dev33</groupId>
    <artifactId>sa-token-spring-boot-starter</artifactId>
    <version>1.30.0</version>
</dependency>
```

#### 配置Sa-Token
Sa-Token提供两种配置方式：`配置文件配置`和`代码配置`

- **通过配置文件配置**

在使用`sa-token`本身可以零配置启动，但同时也可以在`application.yml或application.properties`下自定义配置，具体如下：

```yaml
# Sa-Token基础配置
sa-token:
  # token 名称 (同时也是cookie名称)
  token-name: satoken
  # token 有效期，单位s 默认30天, -1代表永不过期
  timeout: 2592000
  # token 临时有效期 (指定时间内无操作就视为token过期) 单位: 秒
  activity-timeout: -1
  # 是否允许同一账号并发登录 (为true时允许一起登录, 为false时新登录挤掉旧登录)
  is-concurrent: true
  # 在多人登录同一账号时，是否共用一个token (为true时所有登录共用一个token, 为false时每次登录新建一个token)
  is-share: false
  # token风格
  token-style: uuid
  # 是否输出操作日志
  is-log: false
```

- **通过代码配置**

```java
@Configuration
public class SaTokenConfiguration implements WebMvcConfigurer {

    /****************方式1:这个配置会覆盖yml中的配置******************/
    @Bean
    @Primary
    public SaTokenConfig getSaTokenConfigPrimary() {
        SaTokenConfig config = new SaTokenConfig();
        config.setTokenName("satoken");             // token名称 (同时也是cookie名称)
        config.setTimeout(30 * 24 * 60 * 60);       // token有效期，单位s 默认30天
        config.setActivityTimeout(-1);              // token临时有效期 (指定时间内无操作就视为token过期) 单位: 秒
        config.setIsConcurrent(true);               // 是否允许同一账号并发登录 (为true时允许一起登录, 为false时新登录挤掉旧登录)
        config.setIsShare(true);                    // 在多人登录同一账号时，是否共用一个token (为true时所有登录共用一个token, 为false时每次登录新建一个token)
        config.setTokenStyle("uuid");               // token风格
        config.setIsLog(false);                     // 是否输出操作日志
        return config;
    }

    /****************方式2:这个配置会合并yml中的配置******************/
    @Autowired
    public void configSaToken(SaTokenConfig config) {
        config.setTokenName("satoken");             // token名称 (同时也是cookie名称)
        config.setTimeout(30 * 24 * 60 * 60);       // token有效期，单位s 默认30天
        config.setActivityTimeout(-1);              // token临时有效期 (指定时间内无操作就视为token过期) 单位: 秒
        config.setIsConcurrent(true);               // 是否允许同一账号并发登录 (为true时允许一起登录, 为false时新登录挤掉旧登录)
        config.setIsShare(true);                    // 在多人登录同一账号时，是否共用一个token (为true时所有登录共用一个token, 为false时每次登录新建一个token)
        config.setTokenStyle("uuid");               // token风格
        config.setIsLog(false);
    }
}
```

#### 配置项解读

##### sa-token

| 参数名称               |  类型   |        默认值        | 说明                                                         |
| ---------------------- | :-----: | :------------------: | ------------------------------------------------------------ |
| tokenName              | String  |       satoken        | Token 名称 （同时也是 Cookie 名称、数据持久化前缀）          |
| timeout                |  long   |       2592000        | Token 有效期，单位/秒 默认30天，-1代表永久有效 [参考：token有效期详解](https://sa-token.dev33.cn/doc/index.html#/fun/token-timeout) |
| activityTimeout        |  long   |          -1          | Token 临时有效期 （指定时间内无操作就视为token过期） 单位: 秒, 默认-1 代表不限制 （例如可以设置为1800代表30分钟内无操作就过期） [参考：token有效期详解](https://sa-token.dev33.cn/doc/index.html#/fun/token-timeout) |
| isConcurrent           | Boolean |         true         | 是否允许同一账号并发登录 （为 true 时允许一起登录，为 false 时新登录挤掉旧登录） |
| isShare                | Boolean |         true         | 在多人登录同一账号时，是否共用一个token （为 true 时所有登录共用一个 token, 为 false 时每次登录新建一个 token） |
| maxLoginCount          |   int   |          12          | 同一账号最大登录数量，-1代表不限 （只有在 `isConcurrent=true`, `isShare=false` 时此配置才有效），[详解](https://sa-token.dev33.cn/doc/index.html#/use/config?id=maxlogincount) |
| isReadBody             | Boolean |         true         | 是否尝试从 请求体 里读取 Token                               |
| isReadHead             | Boolean |         true         | 是否尝试从 header 里读取 Token                               |
| isReadCookie           | Boolean |         true         | 是否尝试从 cookie 里读取 Token，此值为 false 后，`StpUtil.login(id)` 登录时也不会再往前端注入Cookie |
| tokenStyle             | String  |         uuid         | token风格， [参考：自定义Token风格](https://sa-token.dev33.cn/doc/index.html#/up/token-style) |
| dataRefreshPeriod      |   int   |          30          | 默认数据持久组件实现类中，每次清理过期数据间隔的时间 （单位: 秒） ，默认值30秒，设置为-1代表不启动定时清理 |
| tokenSessionCheckLogin | Boolean |         true         | 获取 `Token-Session` 时是否必须登录 （如果配置为true，会在每次获取 `Token-Session` 时校验是否登录），[详解](https://sa-token.dev33.cn/doc/index.html#/use/config?id=tokensessionchecklogin) |
| autoRenew              | Boolean |         true         | 是否打开自动续签 （如果此值为true, 框架会在每次直接或间接调用 `getLoginId()` 时进行一次过期检查与续签操作），[参考：token有效期详解](https://sa-token.dev33.cn/doc/index.html#/fun/token-timeout) |
| tokenPrefix            | String  |         null         | token前缀，例如填写 `Bearer` 实际传参 `satoken: Bearer xxxx-xxxx-xxxx-xxxx` [参考：自定义Token前缀](https://sa-token.dev33.cn/doc/index.html#/up/token-prefix) |
| isPrint                | Boolean |         true         | 是否在初始化配置时打印版本字符画                             |
| isLog                  | Boolean |        false         | 是否打印操作日志                                             |
| jwtSecretKey           | String  |         null         | jwt秘钥 （只有集成 `sa-token-temp-jwt` 模块时此参数才会生效），[参考：和 jwt 集成](https://sa-token.dev33.cn/doc/index.html#/plugin/jwt-extend) |
| idTokenTimeout         |  long   |        86400         | Id-Token的有效期 （单位: 秒），[参考：内部服务外网隔离](https://sa-token.dev33.cn/doc/index.html#/micro/id-token) |
| basic                  | String  |          ""          | Http Basic 认证的账号和密码 [参考：Http Basic 认证](https://sa-token.dev33.cn/doc/index.html#/up/basic-auth) |
| currDomain             | String  |         null         | 配置当前项目的网络访问地址                                   |
| checkIdToken           | Boolean |        false         | 是否校验Id-Token（部分rpc插件有效）                          |
| cookie                 | Object  | new SaCookieConfig() | Cookie配置对象                                               |

##### cookie

| 参数名称 | 类型    | 默认值 | 说明                                                         |
| -------- | :------ | :----: | ------------------------------------------------------------ |
| domain   | String  |  null  | 作用域（写入Cookie时显式指定的作用域, 常用于单点登录二级域名共享Cookie的场景） |
| path     | String  |   /    | 路径，默认写在域名根路径下                                   |
| secure   | Boolean | false  | 是否只在 https 协议下有效                                    |
| httpOnly | Boolean | false  | 是否禁止 js 操作 Cookie                                      |
| sameSite | String  |  Lax   | 第三方限制级别（Strict=完全禁止，Lax=部分允许，None=不限制） |

##### 单点登录

**server端**

| 参数名称      |  类型   | 默认值 | 说明                                                         |
| ------------- | :-----: | :----: | ------------------------------------------------------------ |
| ticketTimeout |  long   |  300   | ticket 有效期 （单位: 秒）                                   |
| allowUrl      | String  |   *    | 所有允许的授权回调地址，多个用逗号隔开（不在此列表中的URL将禁止下放ticket），参考：[SSO整合：配置域名校验](https://sa-token.dev33.cn/doc/index.html#/sso/sso-check-domain) |
| isSlo         | Boolean | false  | 是否打开单点注销功能                                         |
| isHttp        | Boolean | false  | 是否打开模式三（此值为 true 时将使用 http 请求：校验ticket值、单点注销、获取userinfo），参考：[详解](https://sa-token.dev33.cn/doc/index.html#/use/config?id=ishttp) |
| secretkey     | String  |  null  | 调用秘钥 （用于SSO模式三单点注销的接口通信身份校验）         |

**client端**

| 参数名称       |  类型   | 默认值 | 说明                                                         |
| -------------- | :-----: | :----: | ------------------------------------------------------------ |
| authUrl        | String  |  null  | 配置 Server 端单点登录授权地址                               |
| isSlo          | Boolean | false  | 是否打开单点注销功能                                         |
| isHttp         | Boolean | false  | 是否打开模式三（此值为 true 时将使用 http 请求：校验ticket值、单点注销、获取userinfo），参考：[详解](https://sa-token.dev33.cn/doc/index.html#/use/config?id=ishttp) |
| checkTicketUrl | String  |  null  | 配置 Server 端的 ticket 校验地址                             |
| userinfoUrl    | String  |  null  | 配置 Server 端查询 userinfo 地址                             |
| sloUrl         | String  |  null  | 配置 Server 端单点注销地址                                   |
| ssoLogoutCall  | String  |  null  | 配置当前 Client 端的单点注销回调URL （为空时自动获取）       |
| secretkey      | String  |  null  | 接口调用秘钥 （用于SSO模式三单点注销的接口通信身份校验）     |

##### OAuth 2.0

| 参数名称               |  类型   | 默认值  | 说明                                                         |
| ---------------------- | :-----: | :-----: | ------------------------------------------------------------ |
| isCode                 | Boolean |  true   | 是否打开模式：授权码（`Authorization Code`）                 |
| isImplicit             | Boolean |  false  | 是否打开模式：隐藏式（`Implicit`）                           |
| isPassword             | Boolean |  false  | 是否打开模式：密码式（`Password`）                           |
| isClient               | Boolean |  false  | 是否打开模式：凭证式（`Client Credentials`）                 |
| isNewRefresh           | Boolean |  false  | 是否在每次 `Refresh-Token` 刷新 `Access-Token` 时，产生一个新的 Refresh-Token |
| codeTimeout            |  long   |   300   | Code授权码 保存的时间（单位：秒） 默认五分钟                 |
| accessTokenTimeout     |  long   |  7200   | `Access-Token` 保存的时间（单位：秒）默认两个小时            |
| refreshTokenTimeout    |  long   | 2592000 | `Refresh-Token` 保存的时间（单位：秒） 默认30 天             |
| clientTokenTimeout     |  long   |  7200   | `Client-Token` 保存的时间（单位：秒） 默认两个小时           |
| pastClientTokenTimeout |  long   |  7200   | `Past-Client-Token` 保存的时间（单位：秒） ，默认为-1，代表延续 `Client-Token` 的有效时间 |

---

### 登录认证

#### 认证流程

- 用户登录时需提交`username`和`password`参数,并调用登录接口;
- 服务器校验账号密码,如果验证通过则正常返回数据 并为用户颁发token会话凭证;如果验证未通过会抛出异常,并告知用户需要先登录才能访问;
- 在登陆成功后会返回该用户的token作为会话凭证;
- 在之后的每次请求中都需要携带上token凭证;
- 服务器对携带的token凭证进行判断其是否已经登陆或过期;

#### 登录与注销

- 模拟登录

```java
@RestController
@RequestMapping("/auth")
public class AuthController {

    // 这里省去数据库校验 直接使用固定数据校验
    private final static Long ID = 10001L;
    private final static String USERNAME = "admin";
    private final static String PASSWORD = "123456";

    @PostMapping("/login")
    public SaResult login(String username, String password) {
        // 1.校验用户名和密码
        if (USERNAME.equals(username) && PASSWORD.equals(password)) {
            // 根据ID进行登录
            StpUtil.login(ID);
            return SaResult.ok().setMsg("登陆成功");
        }
        return SaResult.error().setMsg("登陆失败");
    }

    @GetMapping("/logout")
    public SaResult logout() {
        StpUtil.logout();
        return SaResult.ok().setMsg("注销成功");
    }

    @GetMapping("/checkLogin")
    public SaResult checkLogin() {
        StpUtil.checkLogin();
        return SaResult.ok().setMsg("已登陆");
    }

    @GetMapping("/tokenInfo")
    public SaResult tokenInfo() {
        return SaResult.ok().setData(StpUtil.getTokenInfo());
    }
}
```

- 登录结果

![登陆结果](https://img-blog.csdnimg.cn/27e8af9fd68942a88d5f43d3658daade.png)

由上可以看出，只需要一句代码： ` StpUtil.login(Object id)` 便可以使会话登录成功，而实际上，Sa-Token在背后为我们做了大量的工作，主要有：

1.检查此账号是否已被封禁
2.检查此账号是否之前已有登录
3.为账号生成 `Token` 凭证与 `Session` 会话
4.通知全局侦听器，xx 账号登录成功
5.将 `Token` 注入到请求上下文
6.等等其它操作……
*ps:而我们只需要知道`Sa-Token` 为这个账号创建了一个`Token`凭证，且通过`Cookie` 上下文返回给了前端就行了！*

- 注销结果

![注销结果](https://img-blog.csdnimg.cn/3930ac3201214502998c937770243d1b.png)

更多操作语句：

```java
// 获取当前会话是否已经登录，返回true=已登录，false=未登录
StpUtil.isLogin();
// 检验当前会话是否已经登录, 如果未登录，则抛出异常：`NotLoginException`
StpUtil.checkLogin();
```

异常`NotLoginException`代表当前会话暂未登录，可能的原因有很多：前端没有提交 Token、前端提交的 Token 是无效的、前端提交的
Token 已经过期 …… 等等;详情请参看[未登录场景值](https://sa-token.dev33.cn/doc/index-backup.html#/fun/not-login-scene)

#### 其他操作语句

```java
/**
 * 会话查询
 */
// 获取当前会话账号id, 若未登录，则抛出异常：`NotLoginException`
StpUtil.getLoginId();

// 获取当前会话账号id, 并转为String
StpUtil.getLoginIdAsString();   

// 获取当前会话账号id, 并转为int
StpUtil.getLoginIdAsInt();    

// 获取当前会话账号id, 并转为long
StpUtil.getLoginIdAsLong();      

// 获取当前会话登陆时所存入的ID, 若未登录，则返回null 
StpUtil.getLoginIdDefaultNull();

// 获取当前会话登陆时所存入的ID, 若未登录，则返回默认值 （defaultValue可以为任意类型）
StpUtil.getLoginId(T defaultValue);

/*
 * token查询
 */
// 获取当前会话的token值
StpUtil.getTokenValue();

// 获取当前`StpLogic`的token名称
StpUtil.getTokenName();

// 获取指定token对应的账号id，如果未登录，则返回 null
StpUtil.getLoginIdByToken(String tokenValue);

// 获取当前会话剩余有效期（单位：s，返回-1代表永久有效）
StpUtil.getTokenTimeout();

// 获取当前会话的token信息参数
StpUtil.getTokenInfo();
```

---

### 权限认证

在我们的实际业务开发中，除去登陆验证外最重要的就是权限验证。所谓权限验证即校验当前的已登录的账号具有哪些权限，从而在用户请求时判断用户是否具有这个权限，若有该权限时就通过请求，若没有该权限就禁止该用户访问。前端的鉴权只是一个辅助功能，对于专业人员这些限制都是可以轻松绕过的，为保证服务器安全，无论前端是否进行了权限校验，后端接口都需要对会话请求再次进行权限校验！通过查看底层代码可以发现每个账号在底层都会有一个权限码集合，哟用来校验访问的权限是否在这个集合之中。

举个例子：用户`admin`有`["user:list","user:update","user:insert","user:delete"]`权限码集合，用户`test`只有`["user:list"]`权限码集合。此时登录用户`admin`时所有权限都可校验通过，而使用`test`登录时只有一个权限可用，在访问集合中没有的权限时就会抛出`NotPermissionException `异常。

#### 获取当前账户的权限码集合

根据业务需求不同，权限设计也是千变万化，但获取当前用户的权限码集合这一操作是必不可少的。所以，在sa-token中有`StpInterface `接口，可根据自己的业务需求进行重写。其中包括连个方法，分别是：

1.`List<String> getPermissionList(Object loginId, String loginType){}`：返回当前账号所拥有的权限码集合；

2.`List<String> getRoleList(Object loginId, String loginType)`{}：返回当前帐号所拥有的角色码集合；

> 参数说明
>
> - loginId：账号ID(也就是登陆时存储的)
> - loginType：账号体系标识 主要用于在多账户认证时使用(这里可以先忽略)

现在，我们只需要自己新建一个类用于自定义权限验证接口扩展并实现`StpInterface `接口的方法，示例代码如下：

```java
@Component
public class StpImpl implements StpInterface {
    /**
     * 返回一个账号所拥有的权限码集合
     */
    @Override
    public List<String> getPermissionList(Object loginId, String loginType) {
        // 通过传递过来的 loginId 去数据库查询该用户所拥有的权限 这里做演示 就不查询数据库了
        List<String> list = new ArrayList<>();
        list.add("user:list");
        list.add("user:insert");
        list.add("user:update");
        list.add("user:delete");
        return list;
    }

    /**
     * 返回一个账号所拥有的角色标识集合 (权限与角色可分开校验)
     */
    @Override
    public List<String> getRoleList(Object loginId, String loginType) {
        // 通过传递过来的 loginId 去数据库查询该用户所拥有的权限 这里做演示 就不查询数据库了
        List<String> list = new ArrayList<>();
        list.add("admin");
        list.add("super-admin");
        return list;
    }
}
```

#### 权限认证

在对权限码集合进行处理后就可以使用下列的相关API进行鉴权了。

```java
// 获取：当前账号所拥有的权限集合
StpUtil.getPermissionList();

// 判断：当前账号是否含有指定权限, 返回true或false
StpUtil.hasPermission("user:update");        

// 校验：当前账号是否含有指定权限, 如果验证未通过，则抛出异常: NotPermissionException 
StpUtil.checkPermission("user:update");        

// 校验：当前账号是否含有指定权限 [指定多个，必须全部验证通过]
StpUtil.checkPermissionAnd("user:update", "user:delete");        

// 校验：当前账号是否含有指定权限 [指定多个，只要其一验证通过即可]
StpUtil.checkPermissionOr("user:update", "user:delete");    
```

*扩展：`NotPermissionException` 对象可通过 `getLoginType()` 方法获取具体是哪个 `StpLogic` 抛出的异常*

#### 角色认证

在sa-token中，角色和权限可以独立验证，相关API如下所示。

```java
// 获取：当前账号所拥有的角色集合
StpUtil.getRoleList();

// 判断：当前账号是否拥有指定角色, 返回true或false
StpUtil.hasRole("admin");        

// 校验：当前账号是否含有指定角色标识, 如果验证未通过，则抛出异常: NotRoleException
StpUtil.checkRole("super-admin");        

// 校验：当前账号是否含有指定角色标识 [指定多个，必须全部验证通过]
StpUtil.checkRoleAnd("super-admin", "admin");        

// 校验：当前账号是否含有指定角色标识 [指定多个，只要其一验证通过即可] 
StpUtil.checkRoleOr("super-admin", "admin");        
```

#### 全局异常捕获

作为开发者，我们对于抛出的错误异常或者错误信息是能够看明白的，而对于用户来讲，他们是不能看明白这些错误信息的，所以对于鉴权失败所抛出的异常，是不能够直接给用户看的，可以创建一个全局异常捕获类，返回统一的格式给前端。此时前端再根据返回的信息对视图层做优化并展示给用户看。

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
	// 全局异常拦截
	@ExceptionHandler
    public SaResult handlerException(Exception e) {
        e.printStackTrace();
        return SaResult.error().setMsg(e.getMessage());
    }
}
```

#### 权限通配符

在sa-token中允许你使用通配符指定`泛权限`，就比如当前帐号拥有`user*`权限时，与之对应的`user:list`、`user:insert`、`user:update`、`user:delete`都将会匹配通过。

```java
// 当拥有 user* 权限时
StpUtil.hasPermission("user:add");        // true
StpUtil.hasPermission("user:update");     // true
StpUtil.hasPermission("menu:insert");     // false

// 当拥有 *:insert 权限时
StpUtil.hasPermission("user:insert");     // false
StpUtil.hasPermission("user:delete");     // true
StpUtil.hasPermission("menu:insert");     // true

// 当拥有 *.js 权限时
StpUtil.hasPermission("index.js");        // true
StpUtil.hasPermission("index.css");       // false
StpUtil.hasPermission("index.html");      // false
```

*注意：当一个账号拥有 `"*"` 权限时，即表示可以验证通过任何权限码 （角色认证同理），这也被叫做上帝权限(ps:真不错 哈哈哈)*



### 踢人下线

踢人下线也就是指对指定的`loginId`的`token`设置为失效状态，此时这个用户便会被强制下线，只能重新登陆。

#### 强制注销

```java
StpUtil.logout(10001);                    // 强制指定账号注销下线 
StpUtil.logout(10001, "phone");           // 强制指定账号指定端注销下线 
StpUtil.logoutByTokenValue("token");      // 强制指定 Token 注销下线 
```

#### 踢人下线

```java
StpUtil.kickout(10001);                    // 将指定账号踢下线 
StpUtil.kickout(10001, "phone");           // 将指定账号指定端踢下线
StpUtil.kickoutByTokenValue("token");      // 将指定 Token 踢下线
```

> *强制注销 与 踢人下线区别：*
>
> - 强制注销相当于你自己注销 此时你的token会提示无效
> - 踢人下线不会清楚token的信息 只是对这个账户做特定标记 会提示token已被踢下线

#### 账号封禁

用途在于一些管理者需要对违规的账号进行封禁，只是踢下线还可以在登陆，而封禁也就是禁止了该账号的登录。可以在封禁时设置封禁的时间，在这个期间内，该用户是不能进行登录的。

> 参数说明：
>
> 参数1：账号ID
>
> 参数2：封禁时间(单位：秒  若为-1时，代表永久封禁)

```java
// 封禁指定账号 
StpUtil.disable(10001, 86400); 

// 查看指定账号是否被封禁 (true=已被封禁, false=未被封禁) 
StpUtil.isDisable(10001); 

// 查看指定账号剩余封禁时间，单位：秒
StpUtil.getDisableTime(10001); 

// 解除封禁
StpUtil.untieDisable(10001); 
```

*注意：若用户正在登录，此时对其进行封禁并不会被立即注销。若要使其立即生效，可以先踢下线在进行封禁，例如：*

```java
// 先踢下线
StpUtil.kickout(10001); 
// 再封禁账号
StpUtil.disable(10001, 86400); 
```

### 注解鉴权

到目前为止，之前学习的各种方法已经可以使我们搭建一个基本的RBAC系统了，但是我们会发现一个问题，当我们在进行鉴权时，会重复的调用那几个方法，会显得有很多的代码冗余，并且这些鉴权是需要写在每一个业务逻辑之中，此时我们的业务逻辑和鉴权逻辑就混在一起了。鉴于系问题，sa-token也为我们提供了解决方案，通过使用注解的方式，优雅的实现鉴权。将鉴权与业务代码分离。

sa-token通过使用一个全局拦截器来完成注解鉴权功能，为了使项目产生不必要负担，拦截器默认是不开启的。因此我们需要手动将sa-token的全局拦截器注册到你的项目中。并且注解鉴权只能使用在`controller`层。

#### 1.注册注解拦截器

- 注解拦截器：`SaAnnotationInterceptor`

新建一个配置类，我这以`SaTokenConfiguration.java`为例。
```java
@Configuration
@EnableWebMvc
public class SaTokenConfiguration implements WebMvcConfigurer {
    /**
     * 注册注解拦截器 排除不需要注解鉴权的接口地址 (与登录拦截器无关)
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 注册注解拦截器
        registry.addInterceptor(new SaAnnotationInterceptor())
                // 不需要鉴权的接口地址
                .addPathPatterns("/**");
    }
}
```

*注意：如果使用的是springboot 2.6.x 以上的版本 可能会出现拦截器失效 粗腰在添加一个`@EnableWebMvc`注解才可正常使用*

#### 2.使用注解鉴权

**注解说明**

- `@SaCheckLogin`：登录认证    只有登录后才能通过；
- `@SaCheckRole("admin")`：角色认证    必须具有指定角色标识才能通过；
- `@SaCheckPermission("user:add")`：权限认证    必须具有指定权限才能通过；
- `@SaCheckSafe`: 二级认证校验    必须二级认证之后才能通过；
- `@SaCheckBasic`: HttpBasic认证    通过 Basic 认证后才能通过；

> 1.`@SaCheckRole`与`@SaCheckPermission`注解可设置校验模式，例如：
>
> ```java
> /**
>  * mode取值说明
>  * SaMode.AND：一组权限必须全部通过。
>  * SaMode.OR：一组权限只需要通过一个。
>  */
> @SaCheckPermission(value = {"user:delete","user:insert"}, mode = SaMode.OR)
> @GetMapping("/test")
> public SaResult test() {
>     return SaResult.ok("访问成功");
> }
> ```
>
> 2.角色权限双重校验 `or校验`
>
> 在某些场景中需要某种角色或者某种权限码  其中一个满足就能通过。
>
> ```java
> /**
>  * 表示仅需要有"user:insert"权限码或角色为"admin"就能通过。
>  * orRole = "admin"：代表需要拥有admin角色即可通过。
>  * orRole = {"admin","super-admin","test"}：代表只要满足其中一个角色即可。
>  * orRole = {"admin,super-admin,test"}：代表必须同时具备三种角色才能通过。
>  */
> @SaCheckPermission(value = "user:insert", orRole = "admin")
> @GetMapping("/test")
> public SaResult test() {
>     return SaResult.ok("访问成功");
> }
> ```

示例代码：

```java
@RestController
@RequestMapping("/auth")
public class AuthController {
    // 这里省去数据库校验 直接使用固定数据校验
    private final static Long ID = 10001L;
    private final static String USERNAME = "admin";
    private final static String PASSWORD = "123456";

    @PostMapping("/login")
    public SaResult login(String username, String password) {
        // 1.校验用户名和密码
        if (USERNAME.equals(username) && PASSWORD.equals(password)) {
            // 根据ID进行登录
            StpUtil.login(ID);
            return SaResult.ok().setMsg("登陆成功");
        }
        return SaResult.error().setMsg("登陆失败");
    }

    @GetMapping("/logout")
    public SaResult logout() {
        StpUtil.logout();
        return SaResult.ok().setMsg("注销成功");
    }

    @GetMapping("/checkLogin")
    public SaResult checkLogin() {
        StpUtil.checkLogin();
        return SaResult.ok().setMsg("已登陆");
    }

    /**
     * 登录认证
     */
    @SaCheckLogin
    @GetMapping("/tokenInfo")
    public SaResult tokenInfo() {
        return SaResult.ok().setData(StpUtil.getTokenInfo());
    }

    /**
     * 权限认证
     */
    @SaCheckPermission("user:delete")
    @DeleteMapping("/delete")
    public SaResult delete() {
        return SaResult.ok("删除成功");
    }

    @SaCheckPermission("user:insert")
    @PostMapping("/insert")
    public SaResult insert() {
        return SaResult.ok("新增成功");
    }

    @SaCheckPermission("user:list")
    @GetMapping("/list")
    public SaResult list() {
        return SaResult.ok("查询列表成功");
    }

    @SaCheckPermission("user:update")
    @PutMapping("/update")
    public SaResult update() {
        return SaResult.ok("更新成功");
    }

    /**
     * 由于没有user:other权限 此时访问会提示无权限
     */
    @SaCheckPermission("user:other")
    @GetMapping("/other")
    public SaResult other() {
        return SaResult.ok("其他操作");
    }

    /**
     * 角色认证
     */
    @SaCheckRole("admin")
    @GetMapping("/isRole")
    public SaResult isRole() {
        return SaResult.ok("角色认证通过");
    }

    /**
     * 二级认证
     */
    @SaCheckSafe
    @GetMapping("/doubleCheck")
    public SaResult doubleCheck() {
        return SaResult.ok("二级验证通过");
    }

    /**
     * Http Basic 认证
     */
    @SaCheckBasic(account = "sa:admin")
    @GetMapping("/httpBasic")
    public SaResult httpBasic() {
        return SaResult.ok("httpBasic验证通过");
    }
}
```

### 路由鉴权

#### 1.注册路由拦截器

- 路由拦截器：`SaRouteInterceptor`

#### 2.默认的登录校验

> new SaRouteInterceptor()是最简单的无参构造写法，代表只进行默认的登录校验功能。

```java
@Configuration
@EnableWebMvc
public class SaTokenConfiguration implements WebMvcConfigurer {
    // 放行白名单(除白名单内的接口 其余的都需要验证)
    private static final String[] WHITELIST = {"/auth/login"};

    /**
     * 注册路由拦截器(只进行默认的登录校验功能)
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new SaRouteInterceptor())
                .addPathPatterns("/**")
                // 白名单
                .excludePathPatterns(WHITELIST);
    }
}
```

#### 3.自定义认证规则

```java
@Configuration
@EnableWebMvc
public class SaTokenConfiguration implements WebMvcConfigurer {
    /**
     * 注册路由拦截器(自定义拦截规则)
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new SaRouteInterceptor((req, res, handler) -> {
            // 登录认证    拦截所有路由，并排除/user/doLogin 用于开放登录
            SaRouter.match("/**", "/auth/login", r -> StpUtil.checkLogin());

            // 角色认证    拦截以 test 开头的路由，必须具备 admin 角色或者 super-admin 角色才可以通过认证
            SaRouter.match("/test/**", r -> StpUtil.checkRoleOr("admin", "super-admin"));

            // 权限认证    不同模块认证不同权限
            SaRouter.match("/test/**", r -> StpUtil.checkPermission("test"));
            SaRouter.match("/admin/**", r -> StpUtil.checkPermission("admin"));
            SaRouter.match("/super-admin/**", r -> StpUtil.checkPermission("super-admin"));
        })).addPathPatterns("/**");
    }
}
```

#### 4.匹配特征

```java
// 基础写法 即/auth(也可以写多个)下的所有接口需要登录才能通过
SaRouter.match("/auth/**").check(r -> StpUtil.checkLogin());

// 根据请求类型匹配 
SaRouter.match(SaHttpMethod.GET).check(r -> {});

// 多条件匹配
SaRouter
    .match(SaHttpMethod.POST)
    .match("/admin/**")
    .match("/**/send/**") 
    .notMatch("/**/*.js")
    .notMatch("/**/*.css")
    // ....
    .check(r -> {});

/**
 * 提前退出匹配链
 * stop():停止匹配 并且忽略后面剩余的匹配 进入controller
 * back():停止匹配 直接向前端返回结果
 */
SaRouter.match("/**").check(r -> {}).stop();
SaRouter.match("/**").check(r -> {}).back();
```

#### 5.作用域

free作用域是指打开一个独立的作用域，使内部的 stop() 不再一次性跳出整个 Auth 函数，而是仅仅跳出当前 free 作用域。

```java
// 进入 free 独立作用域 
SaRouter.match("/**").free(r -> {
    SaRouter.match("/a/**").check(r -> {});
    SaRouter.match("/a/**").check(r -> {}).stop();
    SaRouter.match("/a/**").check(r -> {});
});
// 执行 stop() 函数跳出 free 后继续执行下面的 match 匹配 
SaRouter.match("/**").check(r -> {});
```

### session会话

session是我们在开发中常用到的数据缓存组件，通过使用session我们可以缓存一些高频读写的数据，从而提高程序性能。在sa-token中session的基础使用也是比较简单，例如：

```java
String data = "hello word!";
// 设置缓存
StpUtil.getSession().set("data", data);

// 读取缓存
String data = (String) StpUtil.getSession().get("data");
```

sa-token中session分类：

- `User-Session`: 框架为每个 账号id 分配的 Session
- `Token-Session`: 框架为每个 token 分配的 Session
- `Custom-Session`: 以一个 特定的值 作为SessionId，来分配的 Session

#### user-session

```java
// 获取当前账号id的Session (必须是登录后才能调用)
StpUtil.getSession();

// 获取当前账号id的Session, 并决定在Session尚未创建时，是否新建并返回
StpUtil.getSession(true);

// 获取账号id为10001的Session
StpUtil.getSessionByLoginId(10001);

// 获取账号id为10001的Session, 并决定在Session尚未创建时，是否新建并返回
StpUtil.getSessionByLoginId(10001, true);

// 获取SessionId为xxxx-xxxx的Session, 在Session尚未创建时, 返回null 
StpUtil.getSessionBySessionId("xxxx-xxxx");
```

#### token-session

```java
// 获取当前token的专属Session 
StpUtil.getTokenSession();

// 获取指定token的专属Session 
StpUtil.getTokenSessionByToken(token);
```

#### custom-session

```java
// 查询指定key的Session是否存在
SaSessionCustomUtil.isExists("goods-10001");

// 获取指定key的Session，如果没有，则新建并返回
SaSessionCustomUtil.getSessionById("goods-10001");

// 获取指定key的Session，如果没有，第二个参数决定是否新建并返回  
SaSessionCustomUtil.getSessionById("goods-10001", false);   

// 删除指定key的Session
SaSessionCustomUtil.deleteSessionById("goods-10001");
```

#### session环境隔离

所谓环境隔离是指SaSession与HttpSession是没有任何关系的，也就是说两者之间的存值取值是不共用的，HttpSession 没有被框架接管，也建议如果使用sa-token框架的话就不尽量不使用HttpSession 。

```java
@GetMapping("/test")
public void reset(HttpSession session) {
    // 用HttpSession存值 
    session.setAttribute("test", 123);
    // 用SaSession取值
    System.out.println(StpUtil.getSession().getAttribute("test"));    // 结果：null
}
```

---

## 深入使用

### 集成Redis

Sa-token 默认是将数据保存在内存中，这样可以使读写速度加快，且避免了序列化与反序列化带来的性能消耗，但是这样做也有一些缺点，比如重启后数据丢失，分布式环境数据无法共享等问题。所以在Sa-Token中提供了扩展接口，使你可以将数据存储于`Redis`、`Memcached`等缓存中间件之中。从而达到数据不丢失，且可共享的目的。

#### 依赖引入

-  jdk 默认序列化方式

> 优点：兼容性好
>
> 缺点：序列化后基本不可读

```xml
<dependency>
    <groupId>cn.dev33</groupId>
    <artifactId>sa-token-dao-redis</artifactId>
    <version>1.30.0</version>
</dependency>
```

-  jackson 序列化方式

> 优点：序列化后可读性强 灵活易修改
>
> 缺点：兼容性差

```xml
<dependency>
    <groupId>cn.dev33</groupId>
    <artifactId>sa-token-dao-redis-jackson</artifactId>
    <version>1.30.0</version>
</dependency>
```

#### Redis序列化配置

```java
@Configuration
@EnableCaching// 开启缓存
public class RedisConfiguration {

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();

        // 设置 key 值序列化方式
        StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();
        redisTemplate.setKeySerializer(stringRedisSerializer);
        redisTemplate.setHashKeySerializer(stringRedisSerializer);
        // 设置 value 值序列化方式
        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(Object.class);
        redisTemplate.setValueSerializer(jackson2JsonRedisSerializer);
        redisTemplate.setHashValueSerializer(jackson2JsonRedisSerializer);

        redisTemplate.setConnectionFactory(redisConnectionFactory);
        return redisTemplate;
    }

}
```

#### Redis配置文件

```yaml
# 端口
spring: 
    # redis配置 
    redis:
        # Redis数据库索引（默认为0）
        database: 1
        # Redis服务器地址
        host: 127.0.0.1
        # Redis服务器连接端口
        port: 6379
        # Redis服务器连接密码（默认为空）
        # password: 
        # 连接超时时间
        timeout: 10s
        lettuce:
            pool:
                # 连接池最大连接数
                max-active: 200
                # 连接池最大阻塞等待时间（使用负值表示没有限制）
                max-wait: -1ms
                # 连接池中的最大空闲连接
                max-idle: 10
                # 连接池中的最小空闲连接
                min-idle: 0
```

### 前后端分离

在之前的文章中，我们使用的是常规的web鉴权方案，由cookie模式完成，其特性包括：由后端写入，每一次请求都会自动提交。这样的鉴权一般由后端控制完成，在前端不需要做任何的操作，而在app、小程序等前后端分离的场景中是不存在cookie这个东西，这时候就需要使用到Token进行鉴权。这时候就只需要后端生成token后将token传递到前端，在之后的每一次提交都不能是自动提交，而使用手动提交，这时候就需要前端将token传递到后端并解析是否正确或过期等问题。

#### Token鉴权

> token详细信息：`StpUtil.getTokenInfo()`
>
> - 此方法会返回一个对象，其中包括两个属性：`tokenName`和`tokenValue`。
> - 可以将这个对象传递到前端并由前端保存到本地即可。

示例代码：

```java
@RestController
@RequestMapping("/auth")
public class AuthController {

    // 这里省去数据库校验 直接使用固定数据校验
    private final static Long ID = 10001L;
    private final static String USERNAME = "admin";
    private final static String PASSWORD = "123456";

    @PostMapping("/login")
    public SaResult login(String username, String password) {
        // 1.校验用户名和密码
        if (USERNAME.equals(username) && PASSWORD.equals(password)) {
            // 根据ID进行登录
            StpUtil.login(ID);
            // 生成token对象
            SaTokenInfo tokenInfo = StpUtil.getTokenInfo();
            // 设置token信息到响应头
            response.setHeader(tokenInfo.getTokenName(), tokenInfo.getTokenValue());
            return SaResult.ok().setMsg("登陆成功");
        }
        return SaResult.error().setMsg("登陆失败");
    }
}
```

#### 自定义Token风格

> 只需要在yml配置文件里设置 `sa-token.token-style=风格类型` 即可

```java
// 1. token-style=uuid    —— uuid风格 (默认风格)
"623368f0-ae5e-4475-a53f-93e4225f16ae"

// 2. token-style=simple-uuid    —— 同上，uuid风格, 只不过去掉了中划线
"6fd4221395024b5f87edd34bc3258ee8"

// 3. token-style=random-32    —— 随机32位字符串
"qEjyPsEA1Bkc9dr8YP6okFr5umCZNR6W"

// 4. token-style=random-64    —— 随机64位字符串
"v4ueNLEpPwMtmOPMBtOOeIQsvP8z9gkMgIVibTUVjkrNrlfra5CGwQkViDjO8jcc"

// 5. token-style=random-128    —— 随机128位字符串
"nojYPmcEtrFEaN0Otpssa8I8jpk8FO53UcMZkCP9qyoHaDbKS6dxoRPky9c6QlftQ0pdzxRGXsKZmUSrPeZBOD6kJFfmfgiRyUmYWcj4WU4SSP2ilakWN1HYnIuX0Olj"

// 6. token-style=tik    —— tik风格
"gr_SwoIN0MC1ewxHX_vfCW3BothWDZMMtx__"
```

#### 自定义Token生成策略

如果你觉着以上风格都不是你喜欢的类型，那么你还可以**自定义token生成策略**，来定制化token生成风格。只需要重写 `SaStrategy` 策略类的 `createToken` 算法，再次调用`StpUtil.login()`方法即可：

```java
@Configuration
public class SaTokenConfigure {
    /**
     * 重写 Sa-Token 框架内部算法策略 
     */
    @Autowired
    public void rewriteSaStrategy() {
        // 重写 Token 生成策略 
        SaStrategy.me.createToken = (loginId, loginType) -> {
            return SaFoxUtil.getRandomString(60);    // 随机60位长度字符串
        };
    }
}
```

#### 自定义Token前缀

在某些系统开发中，需要自定义token的前缀，此时我们只需要做如下配置即可：

```yaml
sa-token: 
    # token前缀
    token-prefix: Bearer 
```

此时token的样式为：

```json
{
    "satoken": "Bearer xxxx-xxxx-xxxx-xxxx"
}
```

*注意：在token前缀与token值之前必须存在一个空格，且在之后的提交中都必须带上前缀。由于cookie中不能存空格，也就意味着如果使用了前缀的话，cookie将会失效，这时候就需要将token放于header中传输，具体请参考Token鉴权代码。*

### 记住我

在一些登陆界面会经常会看到`记住我`的按钮，勾选记住我之后，当你把浏览器关闭后再打开，也依旧是登陆状态，不用重复登陆。而Sa-Token默认的登陆模式就是`记住我`模式，具体只需要在登陆时设置第二参数的值即可。

```java
// true:开启记住我  false:关闭记住我
StpUtil.login(10001, false);
```

### 集成JWT

#### 引入依赖

```xml
<!-- Sa-Token 整合 jwt -->
<dependency>
    <groupId>cn.dev33</groupId>
    <artifactId>sa-token-jwt</artifactId>
    <version>1.30.0</version>
</dependency>
```

> 注意: sa-token-jwt 显式依赖 hutool-all 5.7.14 版本，意味着：你的项目中要么不引入 Hutool，要么引入版本 >= 5.7.14 的 Hutool 版本.

#### 配置jwt

```yml
sa-token:
    # jwt秘钥 
    jwt-secret-key: asdfghjkl
```

#### 注入jwt

> 共有3中注入方式，选其一即可：
>
> 1.Simple 模式：Token 风格替换
>
> 2.Mixin 模式：混入部分逻辑
>
> 3.Stateless 模式：服务器完全无状态

示例代码：

```java
@Configuration
public class SaTokenConfigure {

    @Bean
    public StpLogic getStpLogicJwt() {
        // Simple 简单模式
        return new StpLogicJwtForSimple();
        // Mixin 混入模式
        //return new StpLogicJwtForMixin();
        // Stateless 无状态模式
        //return new StpLogicJwtForStateless();
    }
}
```

#### 扩展参数

```java
// 登录10001账号，并为生成的 Token 追加扩展参数name
StpUtil.login(10001, SaLoginConfig.setExtra("name", "zhangsan"));

// 连缀写法追加多个
StpUtil.login(10001, SaLoginConfig
                .setExtra("name", "zhangsan")
                .setExtra("age", 18)
                .setExtra("role", "超级管理员"));

// 获取扩展参数 
String name = StpUtil.getExtra("name");
```

- 多账户模式集成JWT

```java
@Autowired
public void setUserStpLogic() {
    StpUserUtil.stpLogic = new StpLogicJwtForSimple(StpUserUtil.TYPE);
    SaManager.putStpLogic(StpUserUtil.stpLogic);
}
```

### 密码加密

严格来讲`密码加密`并不属于权限认证的范畴，但是在绝大多数的系统中，为了保证安全都会对密码进行加密，在Sa-Token也封装了一些常见的加密算法。主要包括：`md5`、	`sha1`、`sha256`、`aes`、`rsa`等；

#### 摘要加密

主要包括：`md5`、`sha1`、`sha256`

```java
// md5加密 
SaSecureUtil.md5("123456");

// sha1加密 
SaSecureUtil.sha1("123456");

// sha256加密 
SaSecureUtil.sha256("123456");

// md5加盐加密: md5(md5(str) + md5(salt)) 
SaSecureUtil.md5BySalt("123456", "salt");
```

#### 对称加密

主要是：`aes加密`

```java
// 定义秘钥和明文
String key = "shujfgnugrnsihgsi";
String text = "123456";

// 加密 
String ciphertext = SaSecureUtil.aesEncrypt(key, text);
System.out.println("AES加密后：" + ciphertext);

// 解密 
String text2 = SaSecureUtil.aesDecrypt(key, ciphertext);
System.out.println("AES解密后：" + text2);
```

#### 非对称加密

主要是：`rsa加密`

- 首先生成公/私钥

```java
// 生成一对公钥和私钥，其中Map对象 (private=私钥, public=公钥)
System.out.println(SaSecureUtil.rsaGenerateKeyPair());
```

- 加密解密

```java
// 定义私钥和公钥 
String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAO+wmt01pwm9lHMdq7A8gkEigk0XKMfjv+4IjAFhWCSiTeP7dtlnceFJbkWxvbc7Qo3fCOpwmfcskwUc3VSgyiJkNJDs9ivPbvlt8IU2bZ+PBDxYxSCJFrgouVOpAr8ar/b6gNuYTi1vt3FkGtSjACFb002/68RKUTye8/tdcVilAgMBAAECgYA1COmrSqTUJeuD8Su9ChZ0HROhxR8T45PjMmbwIz7ilDsR1+E7R4VOKPZKW4Kz2VvnklMhtJqMs4MwXWunvxAaUFzQTTg2Fu/WU8Y9ha14OaWZABfChMZlpkmpJW9arKmI22ZuxCEsFGxghTiJQ3tK8npj5IZq5vk+6mFHQ6aJAQJBAPghz91Dpuj+0bOUfOUmzi22obWCBncAD/0CqCLnJlpfOoa9bOcXSusGuSPuKy5KiGyblHMgKI6bq7gcM2DWrGUCQQD3SkOcmia2s/6i7DUEzMKaB0bkkX4Ela/xrfV+A3GzTPv9bIBamu0VIHznuiZbeNeyw7sVo4/GTItq/zn2QJdBAkEA8xHsVoyXTVeShaDIWJKTFyT5dJ1TR++/udKIcuiNIap34tZdgGPI+EM1yoTduBM7YWlnGwA9urW0mj7F9e9WIQJAFjxqSfmeg40512KP/ed/lCQVXtYqU7U2BfBTg8pBfhLtEcOg4wTNTroGITwe2NjL5HovJ2n2sqkNXEio6Ji0QQJAFLW1Kt80qypMqot+mHhS+0KfdOpaKeMWMSR4Ij5VfE63WzETEeWAMQESxzhavN1WOTb3/p6icgcVbgPQBaWhGg==";
String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDvsJrdNacJvZRzHauwPIJBIoJNFyjH47/uCIwBYVgkok3j+3bZZ3HhSW5Fsb23O0KN3wjqcJn3LJMFHN1UoMoiZDSQ7PYrz275bfCFNm2fjwQ8WMUgiRa4KLlTqQK/Gq/2+oDbmE4tb7dxZBrUowAhW9NNv+vESlE8nvP7XXFYpQIDAQAB";

// 文本
String text = "123456";

// 使用公钥加密
String ciphertext = SaSecureUtil.rsaEncryptByPublic(publicKey, text);
System.out.println("公钥加密后：" + ciphertext);

// 使用私钥解密
String text2 = SaSecureUtil.rsaDecryptByPrivate(privateKey, ciphertext);
System.out.println("私钥解密后：" + text2); 
```

#### Base64编码与解码

```java
// 文本
String text = "123456";

// 使用Base64编码
String base64Text = SaBase64Util.encode(text);
System.out.println("Base64编码后：" + base64Text);

// 使用Base64解码
String text2 = SaBase64Util.decode(base64Text);
System.out.println("Base64解码后：" + text2); 
```

### 同端互斥登录

这里举一个很简单的例子，就好比我们使用微信，在手机登录了之后在使用电脑进行登录，此时两个设备是可以同时存在的，但当我们使用手机登陆之后，在使用另一部手机进行登录的话会发现另外一台手机会被挤下线。在同一类型设备上只允许单地点登录，也就是我们常说的被挤下线，在不同类型设备上允许同时在线。

在Sa-Token中要实现同端互斥登录的话，首先需要在配置文件中将`isConcurrent `设置为`false`，然后在去调用相关的API接口即可。

#### 指定登录设备类型

在登录的时候我们就可以指定当前登录的设备的类型，只需要在登录的API上添加即可，如：

```java
// 指定设备类型为phone
StpUtil.login(10001, "phone");    
// 指定设备类型为PC
//StpUtil.login(10001, "PC");    
```
*在使用此方法登陆时，同设备的会被顶下线（不同设备不受影响），再次访问系统时会抛出`NotLoginException`异常，场景值=`-4`*

#### 指定登录设备类型强制注销

只需要在注销时注明注销的设备类型即可；

```java
StpUtil.logout(10001, "PC");    
```
*如果第二个参数填写`null`或不填，代表将这个账号id所有在线端强制注销，被踢出者再次访问系统时会抛出 `NotLoginException` 异常，场景值=`-2`*

#### 查询当前登录设备类型
```java
// 返回当前token的登录设备类型
StpUtil.getLoginDevice();    
```

#### 使用ID反查Token
```
// 获取指定loginId指定设备类型端的tokenValue 
StpUtil.getTokenValueByLoginId(10001, "APP");    
```

### 二级认证

在一些比较敏感的操作的时候，我们需要对已经登录的用户再次进行二次操作。这更加安全的保护了用户的信息安全，假设在删除某些资源的时候就需要使用到二级验证。来确定是否为本人操作或确定是否删除。从而来保证是否为账户本人在操作，避免误删重要数据。在已登录会话的基础上，进行再次验证，提高会话的安全性。

#### 相关API

```java
// 在当前会话 开启二级认证 并设置时间为120(单位：秒)
StpUtil.openSafe(120); 

// 查询当前会话是否处于二级认证时间内
StpUtil.isSafe(); 

// 检查当前会话是否已通过二级认证 若未通过则抛出异常
StpUtil.checkSafe(); 

// 获取当前会话的二级认证剩余有效时间 (单位: 秒, 返回-2代表尚未通过二级认证)
StpUtil.getSafeTime(); 

// 在当前会话 结束二级认证
StpUtil.closeSafe(); 
```

*在前面我们提到了注解，在这里也可以使用注解`@SaCheckSafe `来进行二次验证。具体如下：*

```java
@SaCheckSafe      
@RequestMapping("user-insert")
public String insert() {
    return "用户增加";
}
```

### Http Basic认证

Http Basic 是 http 协议中最基础的认证方式，其有两个特点：

- 简单、易集成。

- 功能支持度低。

在 Sa-Token 中使用 Http Basic 认证非常简单，只需调用几个简单的方法：

**配置二级账户**
```yaml
# 表示账户名：user 密码：123456
sa-token:
  basic: user:123456
```
#### 代码启用Http Basic认证

```java
@RequestMapping("test")
public SaResult test() {
    SaBasicUtil.check("user:123456");// 通过
    //SaBasicUtil.check("user:123123");// 未通过
    // ... 其他代码
    return SaResult.ok();
}
```

**全局异常处理**

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler
    public SaResult handlerException(Exception e) {
        e.printStackTrace(); 
        return SaResult.error(e.getMessage());
    }
}
```

#### 注解启用Http Basic认证

```java
@SaCheckBasic(account = "user:123456")
@RequestMapping("test")
public SaResult test() {
    return SaResult.ok();
}

// 在全局拦截器 或 过滤器中启用 Basic 认证 
@Bean
public SaServletFilter getSaServletFilter() {
    return new SaServletFilter()
            .addInclude("/**").addExclude("/favicon.ico")
            .setAuth(object -> {
                SaRouter.match("/test/**", () -> SaBasicUtil.check("user:123456"));
            });
}
```

### 全局侦听器
接口`SaTokenListener`是`Sa-Token`的全局侦听器，通过实现此接口，你可以在用户登陆、退出、被踢下线等关键性操作时进行一些AOP操作。

框架对此侦听器的默认实现是log日志输出，你可以通过配置`sa-token.is-log=true`开启。

#### 自定义侦听器

```java
/**
 * 自定义侦听器的实现 
 */
@Component
public class GlobalListenerimplements SaTokenListener {

    /**
     * 每次登录时触发
     */
    @Override
    public void doLogin(String loginType, Object loginId, String tokenValue, SaLoginModel loginModel) {}

    /**
     * 每次注销时触发
     */
    @Override
    public void doLogout(String loginType, Object loginId, String tokenValue) {}

    /**  
     * 每次被踢下线时触发
     */
    @Override
    public void doKickout(String loginType, Object loginId, String tokenValue) {}

    /** 
     * 每次被顶下线时触发
     */
    @Override
    public void doReplaced(String loginType, Object loginId, String tokenValue) {}

    /** 
     * 每次被封禁时触发
     */
    @Override
    public void doDisable(String loginType, Object loginId, long disableTime) {}

    /**  
     * 每次被解封时触发
     */
    @Override
    public void doUntieDisable(String loginType, Object loginId) {}

    /** 
     * 每次创建Session时触发
     */
    @Override
    public void doCreateSession(String id) {}

    /** 
     * 每次注销Session时触发
     */
    @Override
    public void doLogoutSession(String id) {}

}
```

### 全局过滤器

在之前我们有学习到`根据拦截器实现路由拦截鉴权·`，但在大多数web框架中，使用过滤器可以实现同样的功能，这里我们也可以使用Sa-Token全局过滤器来实现路由拦截器鉴权。

既然拦截器已经可以实现路由鉴权，为什么还要用过滤器再实现一遍呢？

1.相比于拦截器，过滤器更加底层，执行时机更靠前，有利于防渗透扫描。
2.过滤器可以拦截静态资源，方便我们做一些权限控制。
3.部分Web框架根本就没有提供拦截器功能，但几乎所有的Web框架都会提供过滤器机制。

过滤器缺点：

1.由于太过底层，导致无法率先拿到HandlerMethod对象，无法据此添加一些额外功能。
2.由于拦截的太全面了，导致我们需要对很多特殊路由(如/favicon.ico)做一些额外处理。
3.在Spring中，过滤器中抛出的异常无法进入全局@ExceptionHandler，我们必须额外编写代码进行异常处理。

Sa-Token同时提供过滤器和拦截器机制，不是为了让谁替代谁，而是为了让大家根据自己的实际业务合理选择，拥有更多的发挥空间。

#### 注册过滤器

```java
@Configuration
public class SaTokenConfigure {

    /**
     * 注册 Sa-Token全局过滤器]
     */
    @Bean
    public SaServletFilter getSaServletFilter() {
        return new SaServletFilter()
                // 指定 拦截路由 与 放行路由
                .addInclude("/**").addExclude("/favicon.ico")
                // 认证函数: 每次请求执行 
                .setAuth(obj -> {
                    System.out.println("---------- 进入Sa-Token全局认证 -----------");
                    // 登录认证 -- 拦截所有路由，并排除/user/doLogin 用于开放登录 
                    SaRouter.match("/**", "/user/doLogin", () -> StpUtil.checkLogin());
                    // 更多拦截处理方式，请参考“路由拦截式鉴权”章节 
                })
                // 异常处理函数：每次认证函数发生异常时执行此函数 
                .setError(e -> {
                    System.out.println("---------- 进入Sa-Token异常处理 -----------");
                    return SaResult.error(e.getMessage());
                })
                // 前置函数：在每次认证函数之前执行
                .setBeforeAuth(r -> {
                    // ---------- 设置一些安全响应头 ----------
                    SaHolder.getResponse()
                    // 服务器名称 
                    .setServer("sa-server")
                    // 是否可以在iframe显示视图： DENY=不可以 | SAMEORIGIN=同域下可以 | ALLOW-FROM uri=指定域名下可以 
                    .setHeader("X-Frame-Options", "SAMEORIGIN")
                    // 是否启用浏览器默认XSS防护： 0=禁用 | 1=启用 | 1; mode=block 启用, 并在检查到XSS攻击时，停止渲染页面 
                    .setHeader("X-XSS-Protection", "1; mode=block")
                    // 禁用浏览器内容嗅探 
                    .setHeader("X-Content-Type-Options", "nosniff");
          });
    }
}
```

### 模拟他人&临时身份切换
何为模拟他人？在以上所说的都是操作当前账号，对当前账号进行各种鉴权操作，但是如果我们需要对其他人的账户进行操作，比如我们想看ID10002有没有某个权限，或者ID10003是不是管理员等等。只需要使用以下API即可：

#### 模拟他人API
```java
// 获取指定账号10001的`tokenValue`值 
StpUtil.getTokenValueByLoginId(10001);

// 将账号10001的会话注销登录
StpUtil.logout(10001);

// 获取账号10001的Session对象, 如果session尚未创建, 则新建并返回
StpUtil.getSessionByLoginId(10001);

// 获取账号10001的Session对象, 如果session尚未创建, 则返回null 
StpUtil.getSessionByLoginId(10001, false);

// 获取账号10001是否含有指定角色标识 
StpUtil.hasRole(10001, "super-admin");

// 获取账号10001是否含有指定权限码
StpUtil.hasPermission(10001, "user:insert");
```

#### 临时身份切换API

将当前会话的身份切换为其它账号；

```java
// 将当前会话[身份临时切换]为其它账号（本次请求内有效）
StpUtil.switchTo(10044);

// 此时再调用此方法会返回 10044 (我们临时切换到的账号id)
StpUtil.getLoginId();

// 结束 [身份临时切换]
StpUtil.endSwitch();
```

### 会话治理

尽管框架将大部分操作提供了简易的封装，但在一些特殊场景下，我们仍需要绕过框架，直达数据底层进行一些操作。

#### 具体API
```java
// 查询所有token
StpUtil.searchTokenValue(String keyword, int start, int size);

// 查询所有账号Session会话
StpUtil.searchSessionId(String keyword, int start, int size);

// 查询所有令牌Session会话
StpUtil.searchTokenSessionId(String keyword, int start, int size);
```

**参数说明**
- `keyword`: 查询关键字，只有包括这个字符串的 token 值才会被查询出来。
- `start`: 数据开始处索引, 值为-1时代表一次性取出所有数据。
- `size`: 要获取的数据条数。

#### 使用示例

```java
// 查询value包括1000的所有token，结果集从第0条开始，返回10条
List<String> tokenList = StpUtil.searchTokenValue("1000", 0, 10);    
for (String token : tokenList) {
    System.out.println(token);
}
```

## 最后

Sa-Token是一个轻量级 `Java` 权限认证框架，其中包括了很多的知识要点，其中不乏有SSO整合、OAuth 2.0以及微服务等等。我这里只是列举了我自己以及大多数人可能使用得到的功能要点，如果想要深入的学习`Sa-Token`可转至官网 [`Sa-Token`](https://sa-token.dev33.cn/)进行学习，希望能帮到大家，祝大家学习愉快！
