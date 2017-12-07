# NPM-简介
## 提供获取和更新npmjs.com配置文件的功能。
`
const  profile  =  require（' npm-profile '）
 配置文件。得到（注册表，{标记}）。那么（result  => {
    // ... 
}）`  
这个实现的API记录在这里：
+ 认证
+ 配置文件编辑（和双因素认证）

# index中几个函数的功能
## profile.adduser(username, email, password, config) → Promise
`profile.adduser(username, email, password, {registry}).then(result => {
  // do something with result.token
})
`  
### 在服务器上创建一个新用户以及一个新的不记名令牌，以便作为此用户的将来验证。这就是你所看到authToken的 .npmrc。如果用户已经存在，那么npm注册表将返回一个错误，但这是注册表特定的，不能保证。
+ username String
+ email String
+ password String
+ config Object
+ registry String (for reference, the npm registry is https://registry.npmjs.org)
+ opts Object, make-fetch-happen 用于设置缓存，代理，SSL CA和重试规则等。
## Promise Value
具有token可以传递到将来的身份验证请求的属性的对象。

## Promise Rejection
指示出错的错误对象。该headers属性将包含响应的HTTP标头。  
如果因为需要OTP而拒绝该操作，code则将被设置为EOTP。  
如果该操作因为来自IP地址而被拒绝，则该操作在该账户上不被允许，则该操作code将被设置为EAUTHIP。否则，代码将会'E'跟随HTTP响应代码，例如Forbidden响应E403。

## profile.login(username, password, config) → Promise
`
profile.login(username, password, {registry}).catch(err => {
  if (err.code === 'otp') {
    return getOTPFromSomewhere().then(otp => {
      return profile.login(username, password, {registry, auth: {otp}})
    })
  }
}).then(result => {
  // 用result.token做些事情 
})
`
## 将您记录到现有的用户。如果用户不存在，则不创建用户。登录意味着生成一个新的不记名令牌用于未来的认证。这是你在一个authToken中使用的.npmrc。
+ username String
+ email String
+ password String
+ config Object
+ registry String (for reference, the npm registry is https://registry.npmjs.org)
+ auth Object, properties: otp — the one-time password from a two-factor authentication device.
+ opts Object, make-fetch-happen用于设置缓存，代理，SSL CA和重试规则等。

## Promise Value
具有token可以传递到将来的身份验证请求的属性的对象。
## Promise Rejection
指示出错的错误对象。  
如果该对象的code属性设置为EOTP那么表示该帐户必须使用双因素身份验证才能登录。再次尝试使用一次性密码。  
如果该对象的code属性设置为EAUTHIP那么表示该帐户只能从某些网络登录，并且该IP不在其中一个网络上。  
如果错误不是这些，那么错误对象将有一个 code属性设置为HTTP响应代码，并headers在响应中包含一个HTTP标头属性。
## profile.get(config) → Promise
`
profile.get(registry, {auth: {token}}).then(userProfile => {
  // do something with userProfile
})
`
## 获取已认证用户的配置文件信息。
+ config Object
+ registry String (for reference, the npm registry is https://registry.npmjs.org)
+ auth Object, properties: token — a bearer token returned from adduser, login or createToken, or, username, password (and optionally otp). Authenticating for this command via a username and password will likely not be supported in the future.
+ opts Object, make-fetch-happen make-fetch-happen选项用于设置缓存，代理，SSL CA和重试规则等。
## Promise Value
一个看起来像这样的对象：  
`
// "*" indicates a field that may not always appear
{
  tfa: null |
       false |
       {"mode": "auth-only", pending: Boolean} |
       ["recovery", "codes"] |
       "otpauth://...",
  name: String,
  email: String,
  email_verified: Boolean,
  created: Date,
  updated: Date,
  cidr_whitelist: null | ["192.168.1.1/32", ...],
  fullname: String, // *
  homepage: String, // *
  freenode: String, // *
  twitter: String,  // *
  github: String    // *
}
`
## Promise Rejection
指示出错的错误对象。
该headers属性将包含响应的HTTP标头。  
如果因为需要OTP而拒绝该操作，code则将被设置为EOTP。  
如果该操作因为来自IP地址而被拒绝，则该操作在该账户上不被允许，则该操作code将被设置为EAUTHIP。  
否则，代码将是HTTP响应代码。

## profile.set(profileData, config) → Promise
`
profile.set({github: 'great-github-account-name'}, {registry, auth: {token}})    
`
更新已认证用户的配置文件信息。
+ profileData 一个对象，这样的，从回来profile.get，但请参阅下面的有关注意事项password，tfa和cidr_whitelist。
+ config Object
registry String (供参考，npm注册表是https://registry.npmjs.org)
auth对象，属性：token-承载令牌从返回 adduser，login或createToken，或，username，password（和任选的otp）。未来可能不支持通过用户名和密码验证此命令。
opts 对象，make-fetch-happen选项用于设置缓存，代理，SSL CA和重试规则等。
## SETTING password
这是用来更改您的密码，并通过get()API 不可见（出于显而易见的原因）。值应该是与对象old 和new属性，其中前者具有用户的当前密码和后者具有所需的新的密码。例如
`profile.set({password: {old: 'abc123', new: 'my new (more secure) password'}}, {registry, auth: {token}})`
## SETTING cidr_whitelist
这个值是一个数组。只允许有效的CIDR范围。要非常小心，因为可以用这个锁定自己的账户。这目前还没有暴露npm出来。  
`profile.set({cidr_whitelist: [ '8.8.8.8/32' ], {registry, auth: {token}})
// ↑ only one of google's dns servers can now access this account.`
## SETTING tfa
启用双因素身份验证是一个多步骤的过程。  
调用profile.get并检查状态tfa。如果pending是真的，那么你需要禁用它profile.set({tfa: {password, mode: 'disable'}, …)。  
profile.set({tfa: {password, mode}}, {registry, auth: {token}})  
请注意，无论您如何进行身份验证，password在此tfa对象中都需要用户。  
mode或者是auth-only它需要一个otp呼叫时login 或createToken，或者mode是auth-and-writes和otp将需要在登录，发布或授权时，其他人访问你的模块。  
请注意，此set调用可能需要otp作为auth对象的一部分。如果需要otp，将通过通常的方式拒绝。  
如果tfa已经启用，那么你只是切换模式，成功的回应意味着你已经完成了。如果tfa属性为空并且tfa 未启用，则表示它们处于挂起状态。
Google Authenticator会使用该响应的tfa属性设置为一个otpauth网址 。您需要将其显示给用户，以便他们添加到其身份验证器应用程序。这通常是作为QRCODE完成的，但您也可以在查询字符串中显示键的值，并且可以键入或复制粘贴。secretotpauth
要完成设置两个因素auth你需要第二次调用 profile.set，tfa设置从用户的身份验证器的两个代码的数组，例如：profile.set(tfa: [otp1, otp2]}, registry, {token})
成功后，您将得到一个结果对象tfa，其中包含一次性使用恢复代码的属性。如果第二个因素丢失，那么这些数据将用于后续认证，通常应该打印并放在安全的地方。
禁用双因素认证是更直接的，所设置的tfa 属性与对象password属性和mode的disable。  
`profile.set({tfa: {password, mode: 'disable'}, {registry, auth: {token}}}`
## Promise Value
反映您所做更改的对象，请参阅说明profile.get。
## Promise Rejection
指示出错的错误对象。  
该headers属性将包含响应的HTTP标头 。  
如果因为需要OTP而拒绝该操作，code则将被设置为EOTP。  
如果该操作因为来自IP地址而被拒绝，则该操作在该账户上不被允许，则该操作code将被设置为EAUTHIP。  
否则，代码将是HTTP响应代码。  
## profile.listTokens(config) → Promise
`profile.listTokens(registry, {token}).then(tokens => {
  // do something with tokens
})
`
获取经过身份验证的用户拥有的所有身份验证令牌的列表。
+ config 
+ registry字符串（供参考，npm注册表是https://registry.npmjs.org）
+ auth对象，属性：token-承载令牌从返回 adduser，login或createToken，或，username，password（和任选的otp）。未来可能不支持通过用户名和密码验证此命令。
+ opts对象，make-fetch-happen选项用于设置缓存，代理，SSL CA和重试规则等。
## Promise Value
+ 一个令牌对象数组。每个令牌对象具有以下属性：
+ 键 - 一个sha512，可以用来删除这个令牌。
+ 标记 - 标记UUID的前六个字符。这应该由用户使用来识别这是什么标记。
+ created - 创建令牌的日期和时间
+ 只读 - 如果为true，则此标记只能用于下载私有模块。重要的是，它不能用于发布。
+ cidr_whitelist - 允许使用该令牌的CIDR范围数组。
## Promise Rejection
指示出错的错误对象。  
该headers属性将包含响应的HTTP标头。  
如果因为需要OTP而拒绝该操作，code则将被设置为EOTP。  
如果该操作因为来自IP地址而被拒绝，则该操作在该账户上不被允许，则该操作code将被设置为EAUTHIP。  
否则，代码将是HTTP响应代码。  
## profile.removeToken(token|key, config) → Promise
`
profile.removeToken(key, registry, {token}).then(() => {
  // token is gone!
})
`  
删除特定的身份验证令牌。
+ token|key字符串，一个完整的身份验证令牌或返回的密钥profile.listTokens。
+ config 目的
+ registry字符串（供参考，npm注册表是https://registry.npmjs.org）
+ auth对象，属性：token-承载令牌从返回 adduser，login或createToken，或，username，password（和任选的otp）。未来可能不支持通过用户名和密码验证此命令。
+ opts对象，make-fetch-happen选项用于设置缓存，代理，SSL CA和重试规则等。
## Promise Rejection
指示出错的错误对象。  
该headers属性将包含响应的HTTP标头。  
如果因为需要OTP而拒绝该操作，code则将被设置为EOTP。  
如果该操作因为来自IP地址而被拒绝，则该操作在该账户上不被允许，则该操作code将被设置为EAUTHIP。  
否则，代码将是HTTP响应代码。  
## profile.createToken(password, readonly, cidr_whitelist, config) → Promise
`profile.createToken(password, readonly, cidr_whitelist, registry, {token, otp}).then(newToken => {
  // do something with the newToken
})`  
创建一个新的身份验证令牌，可能有限制。
+ password 串
+ readonly 布尔
+ cidr_whitelist 
+ config 目的
+ registry字符串（供参考，npm注册表是https://registry.npmjs.org）
+ auth对象，属性：token-承载令牌从返回 adduser，login或createToken，或，username，password（和任选的otp）。未来可能不支持通过用户名和密码验证此命令。
+ opts对象，make-fetch-happen选项用于设置缓存，代理，SSL CA和重试规则等。
## Promise Value
这个承诺将以一个非常像返回的对象来解决 profile.listTokens。唯一的区别token是不被截断。  
`
{
  token: String,
  key: String,    // sha512 hash of the token UUID
  cidr_whitelist: [String],
  created: Date,
  readonly: Boolean
}
`
## Promise Rejection
指示出错的错误对象。  
该headers属性将包含响应的HTTP标头。  
如果因为需要OTP而拒绝该操作，code则将被设置为EOTP。  
如果该操作因为来自IP地址而被拒绝，则该操作在该账户上不被允许，则该操作code将被设置为EAUTHIP。  
否则，代码将是HTTP响应代码。  
## Logging
这个模块通过log在全局process对象上发布事件来记录日志。这些事件看起来像这样：
`process.emit('log', 'loglevel', 'feature', 'message part 1', 'part 2', 'part 3', 'etc')`
loglevel可以是一个：error，warn，notice，http，timing，info，verbose，和silly。  
feature 是任何描述组件进行日志记录的简短字符串。  
其的参数被评估console.log，并与空格连接在一起。  
一个例子是：    
`process.emit('log', 'http', 'request', '→',conf.method || 'GET', conf.target)`
为了处理日志事件，你可以这样做：  
`const log = require('npmlog')
process.on('log', function (level) {
  return log[level].apply(log, [].slice.call(arguments, 1))
})`





























