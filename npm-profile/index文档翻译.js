//在严格模式下写代码 
'use strict'
//引入make-fetch-happen模块（一个node-fetch-npm包含附加功能的Node.js库，node-fetch并不打算包括HTTP缓存支持，请求池，代理，重试等等！），并设置其
//默认属性中的请求重试设置的属性值为false（即不请求重试）。
const fetch = require('make-fetch-happen').defaults({retry: false})
//引入aproba模块（一个轻量级函数参数验证器）
const validate = require('aproba')
//引入url模块（用于URL解析和解析的实用程序）
const url = require('url')

//exports 变量是在模块的文件级别作用域内有效的，它在模块被执行前被赋予 module.exports 的值。
//它有一个快捷方式，以便 module.exports.f = ... 可以被更简洁地写成 exports.f = ...。 
//exports是模块往外暴露方法的接口。
//暴露增加新用户的函数方法
exports.adduser = adduser
//暴露登录的函数方法
exports.login = login
//暴露获取的函数方法
exports.get = get
//暴露设置的函数方法
exports.set = set
//暴露列表token验证方法
exports.listTokens = listTokens
//暴露移除token验证方法
exports.removeToken = removeToken
//暴露创建token验证方法
exports.createToken = createToken

//增加新用户的的函数adduser，传入四个参数（用户名，邮箱，密码，配置）
function adduser (username, email, password, conf) {
  //验证传入的四个参数，用户名必须是字符串类型的，邮箱是字符串类型的，密码是字符串类型的，配置是对象类型的。
  validate('SSSO', arguments)
  //如果不是配置的用户不是
  if (!conf.opts) conf.opts = {}
  //设置常对象用户对象，里面的id属性是'org.couchdb.user:' + username的拼接（为什么org.couchdb.user：前缀？
  //原因就在用户的登录名是有 命名空间，用户属于一个特殊的前缀。这个前缀是为了防止 复制冲突当你尝试合并两个或更多_user数据库.
  //当前CouchDB发布，所有用户都属于同一个org.couchdb.user命名空间，这是无法改变的。）,name属性的属性值是用户名，password的属性的属性值是密码，类型是
  //用户类型，roles的属性值是空数组，date的属性值是返回当前的日期时间
  const userobj = {
    _id: 'org.couchdb.user:' + username,
    name: username,
    password: password,
    email: email,
    type: 'user',
    roles: [],
    date: new Date().toISOString()
  }
  //设置常对象logObj为空对象
  const logObj = {}
  //通过forEach来遍历从userobj里面的每个属性中查找到password的属性，如果找到，就将密码的值以'XXXXX'的形式赋值给logObj对象对应的属性的属性值，如果不
  //不是password属性，就将userobj里对应的属性及属性值赋值给logObj里的对应的属性及属性值
  Object.keys(userobj).forEach(k => {
    logObj[k] = k === 'password' ? 'XXXXX' : userobj[k]
  })
  //当前进程对logObj对象触发打印事件、打印进度信息事件、增加用户事件和在第一次提交事件
  process.emit('log', 'verbose', 'adduser', 'before first PUT', logObj)
  //用后面的标签来替换前面的配置中的记录（encodeURIComponent() 函数可把字符串类型username作为 URI 组件进行编码。）
  const target = url.resolve(conf.registry, '-/user/org.couchdb.user:' + encodeURIComponent(username))
  //返回结果是JSON格式获取到的信息（目标，方法是通过"put"方法获取，主页内容是userobj，参数设置是配置的参数）
  return fetchJSON({target: target, method: 'PUT', body: userobj, opts: conf.opts})
}


//登录函数三个参数（应户名，密码和配置）
function login (username, password, conf) {
  //验证三个参数用户名是否是字符串类型，密码是否是字符串类型，配置是否是对象类型
  validate('SSO', arguments)
  //定义常对象userobj（id，名字，密码，类型，角色，日期）
  const userobj = {
    _id: 'org.couchdb.user:' + username,
    name: username,
    password: password,
    type: 'user',
    roles: [],
    date: new Date().toISOString()
  }
  //初始化常对象打印对象为空对象
  const logObj = {}
  //通过forEach来遍历从userobj里面的每个属性中查找到password的属性，如果找到，就将密码的值以'XXXXX'的形式赋值给logObj对象对应的属性的属性值，如果不
  //是password属性，就将userobj里对应的属性及属性值赋值给logObj里的对应的属性及属性值
  Object.keys(userobj).forEach(k => {
    logObj[k] = k === 'password' ? 'XXXXX' : userobj[k]
  })
  //当前进程触发打印事件、打印进度信息事件、登录事件和在第一次提交事件
  process.emit('log', 'verbose', 'login', 'before first PUT', logObj)
  //用后面的标签来替换前面的配置中的记录（encodeURIComponent() 函数可把字符串类型username作为 URI 组件进行编码。）
  const target = url.resolve(conf.registry, '-/user/org.couchdb.user:' + encodeURIComponent(username))
 //返回通过拷贝配置对象的的JSON对象，并且捕获异常，若果异常代码是 'E400'，则异常的提示信息是用户没有用户名，从后台获取用户名
 //如果异常代码是'E409'，则抛出异常。
  return fetchJSON(Object.assign({method: 'PUT', target: target, body: userobj}, conf)).catch(err => {
    if (err.code === 'E400') err.message = `There is no user with the username "${username}".`
    if (err.code !== 'E409') throw err
 //返回通过'get'方法获取到目标，并且将配置中的属性拷贝到目标中饭=，程序异步执行一个函数，传入result
    return fetchJSON(Object.assign({method: 'GET', target: target + '?write=true'}, conf)).then(result => {
 //循环遍历result里面的所有属性    
      Object.keys(result).forEach(function (k) {
 //判断userobj中如果不存在传入的属性或者是该属性是角色属性的话，将result里面对应的属性的值赋给userobj对应的属性的值
        if (!userobj[k] || k === 'roles') {
          userobj[k] = result[k]
        }
      })
 //定义常对象req，方法是"put"方法，目标属性，内容属性，auth对象里面还有个基础属性，包括用户名和密码
      const req = {
        method: 'PUT',
        target: target + '/-rev/' + userobj._rev,
        body: userobj,
        auth: {
          basic: {
            username: username,
            password: password
          }
        }
      }
 //返回将req对象和conf对象拷贝到的新对象中（JSON格式）
      return fetchJSON(Object.assign({}, conf, req))
    })
  })
}
//获取函数
function get (conf) {
//先验证配置是否是对象类型 
  validate('O', arguments)
// 后面的字符串内容代替配置中的记录
  const target = url.resolve(conf.registry, '-/npm/v1/user')
 //返回将配置对象拷贝到有target属性的对象中去
  return fetchJSON(Object.assign({target: target}, conf))
}
//设置函数
function set (profile, conf) {
//验证两个参数是否都是字符串类型的 
  validate('OO', arguments)
  
  const target = url.resolve(conf.registry, '-/npm/v1/user')
  Object.keys(profile).forEach(key => {
    // profile keys can't be empty strings, but they CAN be null
    if (profile[key] === '') profile[key] = null
  })
  return fetchJSON(Object.assign({target: target, method: 'POST', body: profile}, conf))
}

function listTokens (conf) {
  validate('O', arguments)

  return untilLastPage(`-/npm/v1/tokens`)

  function untilLastPage (href, objects) {
    return fetchJSON(Object.assign({target: url.resolve(conf.registry, href)}, conf)).then(result => {
      objects = objects ? objects.concat(result.objects) : result.objects
      if (result.urls.next) {
        return untilLastPage(result.urls.next, objects)
      } else {
        return objects
      }
    })
  }
}

function removeToken (tokenKey, conf) {
  validate('SO', arguments)
  const target = url.resolve(conf.registry, `-/npm/v1/tokens/token/${tokenKey}`)
  return fetchJSON(Object.assign({target: target, method: 'DELETE'}, conf))
}

function createToken (password, readonly, cidrs, conf) {
  validate('SBAO', arguments)
  const target = url.resolve(conf.registry, '-/npm/v1/tokens')
  const props = {
    password: password,
    readonly: readonly,
    cidr_whitelist: cidrs
  }
  return fetchJSON(Object.assign({target: target, method: 'POST', body: props}, conf))
}

function FetchError (err, method, target) {
  err.method = method
  err.href = target
  return err
}

class HttpErrorBase extends Error {
  constructor (method, target, res, body) {
    super()
    this.headers = res.headers.raw()
    this.statusCode = res.status
    this.code = 'E' + res.status
    this.method = method
    this.target = target
    this.body = body
    this.pkgid = packageName(target)
  }
}

class General extends HttpErrorBase {
  constructor (method, target, res, body) {
    super(method, target, res, body)
    this.message = `Registry returned ${this.statusCode} for ${this.method} on ${this.href}`
  }
}

class AuthOTP extends HttpErrorBase {
  constructor (method, target, res, body) {
    super(method, target, res, body)
    this.message = 'OTP required for authentication'
    this.code = 'EOTP'
    Error.captureStackTrace(this, AuthOTP)
  }
}

class AuthIPAddress extends HttpErrorBase {
  constructor (res, body) {
    super(method, target, res, body)
    this.message = 'Login is not allowed from your IP address'
    this.code = 'EAUTHIP'
    Error.captureStackTrace(this, AuthIPAddress)
  }
}

class AuthUnknown extends HttpErrorBase {
  constructor (method, target, res, body) {
    super(method, target, res, body)
    this.message = 'Unable to authenticate, need: ' + res.headers.get('www-authenticate')
    this.code = 'EAUTHIP'
    Error.captureStackTrace(this, AuthIPAddress)
  }
}

function authHeaders (auth) {
  const headers = {}
  if (!auth) return headers
  if (auth.otp) headers['npm-otp'] = auth.otp
  if (auth.token) {
    headers['Authorization'] = 'Bearer ' + auth.token
  } else if (auth.basic) {
    const basic = auth.basic.username + ':' + auth.basic.password
    headers['Authorization'] = 'Basic ' + Buffer.from(basic).toString('base64')
  }
  return headers
}

function fetchJSON (conf) {
  const fetchOpts = {
    method: conf.method,
    headers: Object.assign({}, conf.headers || (conf.auth && authHeaders(conf.auth)) || {})
  }
  if (conf.body != null) {
    fetchOpts.headers['Content-Type'] = 'application/json'
    fetchOpts.body = JSON.stringify(conf.body)
  }
  process.emit('log', 'http', 'request', '→',conf.method || 'GET', conf.target)
  return fetch.defaults(conf.opts || {})(conf.target, fetchOpts).catch(err => {
    throw new FetchError(err, conf.method, conf.target)
  }).then(res => {
    if (res.headers.get('content-type') === 'application/json') {
      return res.json().then(content => [res, content])
    } else {
      return res.buffer().then(content => {
        try {
          return [res, JSON.parse(content)]
        } catch (_) {
          return [res, content]
        }
      })
    }
  }).then(result => {
    const res = result[0]
    const content = result[1]
    process.emit('log', 'http', res.status, `← ${res.statusText} (${conf.target})`)
    if (res.status === 401 && res.headers.get('www-authenticate')) {
      const auth = res.headers.get('www-authenticate').split(/,\s*/).map(s => s.toLowerCase())
      if (auth.indexOf('ipaddress') !== -1) {
        throw new AuthIPAddress(conf.method, conf.target, res, content)
      } else if (auth.indexOf('otp') !== -1) {
        throw new AuthOTP(conf.method, conf.target, res, content)
      } else {
        throw new AuthUnknown(conf.method, conf.target, res, content)
      }
    } else if (res.status < 200 || res.status >= 300) {
      if (typeof content === 'object' && content.error) {
        return content
      } else {
        throw new General(conf.method, conf.target, res, content)
      }
    } else {
      return content
    }
  })
}

function packageName (href) {
  try {
    let basePath = url.parse(href).pathname.substr(1)
    if (!basePath.match(/^-/)) {
      basePath = basePath.split('/')
      var index = basePath.indexOf('_rewrite')
      if (index === -1) {
        index = basePath.length - 1
      } else {
        index++
      }
      return decodeURIComponent(basePath[index])
    }
  } catch (_) {
    // this is ok
  }
}
