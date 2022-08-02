# Sa-Token

## 简介

官网：[Sa-Token](https://sa-token.dev33.cn/index.html)

sa-token是一个轻量级java权限认证框架，可以使鉴权变得更加优雅、简单！主要解决`登录认证`、`权限认证`、`单点登录`、`OAuth 2.0`
、`分布式session会话`、`微服务网关鉴权`等一系列权限问题！在使用API也是极为简单，只需要通过`StpUtil`即可实现。

---

## 基础使用

### 环境集成

- 在SpringBoot项目中添加依赖

```xml
<!--sa-token-->
<dependency>
    <groupId>cn.dev33</groupId>
    <artifactId>sa-token-spring-boot-starter</artifactId>
    <version>1.30.0</version>
</dependency>
```

- 添加配置文件`application.yml`

```yaml
# Sa-Token配置
sa-token:
  # token 名称 (同时也是cookie名称)
  token-name: authorization
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

---

### 登录认证

#### 认证流程

- 用户登录时提交`username`和`password`参数,并调用登录接口
- 服务器校验账号密码,如果验证通过则正常返回数据 并为用户颁发token会话凭证;如果验证未通过会抛出异常,并告知用户需要先登录
- 登陆成功后会返回该用户的token作为会话凭证
- 在之后的每次请求中,都需要携带上token凭证
- 服务器对携带的token凭证进行判断其是否已经登陆

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

![raw.githubusercontent.com](https://raw.githubusercontent.com/hetongxue303/Sa-Token/master/images/image-20220801221305165.png)

由此可以看出，只需要一句代码 ` StpUtil.login(Object id)` 便可以使会话登录成功，而实际上，Sa-Token在背后为我们做了大量的工作，主要有：

1.检查此账号是否已被封禁
2..检查此账号是否之前已有登录
3.为账号生成 `Token` 凭证与 `Session` 会话
4.通知全局侦听器，xx 账号登录成功
5.将 `Token` 注入到请求上下文
6.等等其它操作……
*ps:而我们只需要知道`Sa-Token` 为这个账号创建了一个`Token`凭证，且通过`Cookie` 上下文返回给了前端就行了！*

- 注销结果

![raw.githubusercontent.com](https://raw.githubusercontent.com/hetongxue303/Sa-Token/master/images/image-20220801221248637.png)

更多操作语句：

```java
// 获取当前会话是否已经登录，返回true=已登录，false=未登录
StpUtil.isLogin();
// 检验当前会话是否已经登录, 如果未登录，则抛出异常：`NotLoginException`
StpUtil.checkLogin();
```

异常`NotLoginException`代表当前会话暂未登录，可能的原因有很多：前端没有提交 Token、前端提交的 Token 是无效的、前端提交的
Token 已经过期 …… 等等;详情请参看[未登录场景值](https://sa-token.dev33.cn/doc/index-backup.html#/fun/not-login-scene)

#### 其他常用操作

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

1.`List<String> getPermissionList(Object loginId, String loginType){}：返回当前账号所拥有的权限码集合；

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

