# Description
#   Assign roles to users and restrict command access in other scripts.
#
# Configuration:
#   HUBOT_AUTH_ADMIN - A comma separate list of user IDs
#
# Commands:
#   hubot auth help - auth commands
#
# Notes:
#   * Call the method: robot.auth.hasRole(msg.envelope.user,'<role>')
#   * returns bool true or false
#
#   * the 'admin' role can only be assigned through the environment variable
#   * roles are all transformed to lower case
#
#   * The script assumes that user IDs will be unique on the service end as to
#     correctly identify a user. Names were insecure as a user could impersonate
#     a user

fs = require 'fs'
moment = require 'moment'

modulename = 'auth'
data_file = modulename + ".json"
timefmt = 'YYYY-MM-DD HH:mm:ss ZZ'
svcQueueIntervalMs = 300 * 1000

robotRef = false
auth_data =
  notify: []
  roles: {}
  duo2fa: {}

config =
  duo: 0
  replyInPrivate: false

if process.env.HUBOT_AUTH_ADMIN
  config.admin_list = process.env.HUBOT_AUTH_ADMIN
else
  console.warn "#{modulename}: HUBOT_AUTH_ADMIN environment variable not set."

if process.env.HUBOT_AUTH_DUO_IKEY
  config.duo_ikey = process.env.HUBOT_AUTH_DUO_IKEY
  config.duo++

if process.env.HUBOT_AUTH_DUO_SKEY
  config.duo_skey = process.env.HUBOT_AUTH_DUO_SKEY
  config.duo++

if process.env.HUBOT_AUTH_DUO_HOST
  config.duo_host = process.env.HUBOT_AUTH_DUO_HOST
  config.duo++

if config.duo == 3
  duo_api = require 'duo_api'
  config.duo = true
  duoclient = new duo_api.Client config.duo_ikey, config.duo_skey,
    config.duo_host
  duoclient.jsonApiCall 'GET', '/auth/v2/check', {}, (res) ->
    unless res.stat is 'OK'
      console.error 'duo api check failed: '+ res.message
      process.exit(1)
  console.info "#{modulename}: duo 2fa enabled"

if process.env.HUBOT_PRIVATE_HELP
  config.replyInPrivate = process.env.HUBOT_PRIVATE_HELP


isAuthorized = (robot, msg, roles=['admin']) ->
  roles = [roles] if typeof roles is 'string'
  return true if robot.auth.isAdmin(msg.envelope.user)
  return true if robot.auth.hasRole(msg.envelope.user,roles)
  errmsg = "#{modulename}: a role of #{roles.join ', '} is required."
  msg.reply errmsg
  who = msg.envelope.user.name
  logmsg = "#{modulename}: #{who} missing #{roles.join ', '} role, not authorized"
  robot.logger.info logmsg
  return false


grant2fa = (robot, msg, user) ->
  expires = moment(auth_data.duo2fa[user])
  if expires.valueOf() > Date.now()
    return msg.reply "#{modulename}: 2fa already granted.  Expires #{expires.fromNow()}."

  auth_data.duo2fa[user] = new moment().add(1,'hours')
  writeData()

  expires = auth_data.duo2fa[user].format(timefmt)
  logmsg = "#{modulename}: #{user} granted 2fa until #{expires}"
  robot.logger.info logmsg

  return msg.reply "#{modulename}: 2fa granted until `#{expires}`."


expirationWorker = ->
  expireEntries()
  setTimeout expirationWorker, svcQueueIntervalMs


expireEntries = ->
  removequeue = []
  for user, expiresdt of auth_data.duo2fa when moment(expiresdt).valueOf() < Date.now()
    removequeue.push user

  if removequeue.length > 0
    while removequeue.length > 0
      delete auth_data.duo2fa[removequeue.shift()]
      usermsg = "#{modulename}: #{user} 2fa grant has expired"
      #robotRef.send { room: user }, usermsg
      robotRef.logger.info usermsg
    writeData()


addAuth = (robot, msg) ->
  who = msg.message.user.name
  role = msg.match[1].trim().toLowerCase()
  user = msg.match[2].trim()

  uid = robot.brain.userForName(user)
  return msg.reply "#{user} does not exist" unless uid?

  if robot.auth.hasRole(user,role)
    return msg.reply "#{user} already has the `#{role}` role."

  if role is 'admin'
    errmsg = "Sorry, the `admin` role can only be defined in the " +
      "`HUBOT_AUTH_ADMIN` env variable."
    return msg.reply errmsg

  robot.auth.addRoleToUser(user,role)

  logmsg = "#{modulename}: #{who} added '#{role}' role to '#{user}' user"
  robot.logger.info logmsg

  return msg.reply "OK, #{user} has the `#{role}` role."


authWho = (robot, msg) ->
  who = msg.message.user.name
  if msg.match[1]?
    user = msg.match[1].trim()
    user = who if user.toLowerCase() is 'i'
    uid = robot.brain.userForName(user)
    return msg.reply "#{user} does not exist" unless uid?
  else
    user = msg.message.user

  return msg.send "#{user.name} is user id `#{user.id}`"


removeAuth = (robot, msg) ->
  who = msg.message.user.name
  role = msg.match[1].trim().toLowerCase()
  user = msg.match[2].trim()

  uid = robot.brain.userForName(user)
  return msg.reply "#{user} does not exist" unless uid?

  if role is 'admin'
    errmsg = "Sorry, the 'admin' role can only be removed from the " +
      "HUBOT_AUTH_ADMIN env variable."
    return msg.reply errmsg

  robot.auth.removeRoleFromUser(user,role)

  logmsg = "#{modulename}: #{who} removed '#{role}' " +
    "role from '#{user}' user"
  robot.logger.info logmsg

  return msg.reply "OK, #{user} doesn't have the `#{role}` role."


listAuthRolesForUser = (robot, msg) ->
  who = msg.message.user.name
  user = msg.match[1].trim()
  user = who if user.toLowerCase() is 'i'

  uid = robot.brain.userForName(user)
  return msg.reply "#{user} does not exist" unless uid?

  userRoles = robot.auth.userRoles(user)

  if userRoles.length == 0
    return msg.reply "#{user} has no roles."

  return msg.reply "#{user} has the following roles: #{userRoles.join(', ')}."


listAuthUsersWithRole = (robot, msg) ->
  role = msg.match[1]
  users = robot.auth.usersWithRole(role)

  if users.length > 0
    return msg.reply "Users with `#{role}` role: `#{users.join('`, `')}`"

  return msg.reply "No one has `#{role}` role."


listAuthRoles = (robot, msg) ->
  roles = robot.auth.roles()

  if roles.length > 0
    return msg.reply "The following roles are available: #{roles.join(', ')}"

  return msg.reply "No roles to list."


duo2faAuth = (robot, msg) ->
  who = msg.message.user.name

  if auth_data.duo2fa[who]
    expires = moment(auth_data.duo2fa[who])
    if expires.valueOf() > Date.now()
      return msg.reply "#{modulename}: 2fa already granted.  Expires #{expires.fromNow()}."

  logmsg = "#{modulename}: #{who} request: 2fa"
  robot.logger.info logmsg

  unless config.duo
    usermsg = "#{modulename}: 2fa not configured"
    return msg.reply usermsg

  usermsg = "#{modulename}: requesting 2fa via duo"
  msg.reply usermsg

  duoclient.jsonApiCall 'POST', '/auth/v2/preauth', { username: who }, (r) ->
    res = r.response
    if res.result is 'enroll'
      logmsg = "#{modulename}: #{who} 2fa: duo enroll"
      robot.logger.info logmsg
      usermsg = "#{modulename}: duo reports: `#{res.status_msg}`. " +
        "Enrollment portal: #{res.enroll_portal_url}"
      return msg.reply usermsg

    if res.result is 'allow'
      logmsg = "#{modulename}: #{who} 2fa: granted"
      robot.logger.info logmsg
      return grant2fa(robot, msg, who)

    if res.result is 'auth'
      return duoclient.jsonApiCall 'POST', '/auth/v2/auth', { username: who, factor: 'auto', device: 'auto' }, (r) ->
        res = r.response
        unless res.result is 'allow'
          logmsg = "#{modulename}: #{who} 2fa: duo api auth failed"
          robot.logger.info logmsg
          return msg.reply "duo api auth failed: #{JSON.stringify(res)}"
        logmsg = "#{modulename}: #{who} 2fa: granted"
        robot.logger.info logmsg
        #msg.reply "#{modulename}: duo reports: `#{res.status_msg}`"
        return grant2fa(robot, msg, who)

    # this should not happen
    usermsg = "Duo reports: result=`#{res.result}` and " +
      "status_message=`#{res.status_message}`\n```#{JSON.stringify(res)}```"
    return msg.reply usermsg


writeData = ->
  fs.writeFileSync data_file, JSON.stringify(auth_data), 'utf-8'
  logmsg = "#{modulename}: wrote #{data_file}"
  robotRef.logger.info logmsg


module.exports = (robot) ->

  robotRef = robot
  setTimeout expirationWorker, svcQueueIntervalMs

  try
    auth_data = JSON.parse fs.readFileSync data_file, 'utf-8'
    robot.logger.info "#{modulename}: read #{data_file}" if robot.logger
  catch error
    unless error.code is 'ENOENT'
      console.error("#{modulename}: unable to read #{data_file}: ", error)

  if config.admin_list?
    admins = config.admin_list.split ','
  else
    admins = []

  class Auth
    username: (user) ->
      un = false
      if typeof user is 'string'
        un = user
      if typeof user is 'object' and user.name?
        un = user.name
      return un

    isAdmin: (user) ->
      un = @username(user)
      un in admins

    is2fa: (user) ->
      un = @username(user)
      return false unless auth_data.duo2fa[un]
      return false unless moment().isBefore(auth_data.duo2fa[un])
      return true

    roles: () ->
      roles = []
      roles.push role for role, users of auth_data.roles
      return roles

    hasRole: (user, roles) ->
      userRoles = @userRoles(user)
      if userRoles?
        roles = [roles] if typeof roles is 'string'
        for role in roles
          return true if role in userRoles
      return false

    usersWithRole: (role) ->
      users = []
      if role not of auth_data.roles
        return []
      return auth_data.roles[role]

    userRoles: (user) ->
      un = @username(user)
      return [] unless un
      roles = []
      if robot.auth.isAdmin user
        roles.push('admin')
      if auth_data.roles?
        for role, users of auth_data.roles when un in users
          roles.push role
      return roles

    addRoleToUser: (user, role) ->
      un = @username(user)
      return false unless un
      if auth_data.roles[role]
        auth_data.roles[role].push un
      else
        auth_data.roles[role] = [un]
      writeData()
      return true

    removeRoleFromUser: (user, role) ->
      un = @username(user)
      return false unless un
      users = @usersWithRole(role)
      un_idx = users.indexOf(un)
      return false if un_idx < 0
      #console.log auth_data.roles[role], users, un, un_idx
      users.splice(un_idx, 1)
      auth_data.roles[role] = users
      #console.log auth_data.roles[role], users, un, un_idx
      writeData()
      return true

  robot.auth = new Auth


  robot.respond /auth(?: help| h|)$/, (msg) ->
    cmds = []
    arr = [
      modulename + " add <role> to <user> - role assignment"
      modulename + " remove <role> from <user> - remove role from user"
      modulename + " list roles for <user> - list roles"
      modulename + " list users with <role> - list users"
      modulename + " list roles - list roles"
      modulename + " 2fa - escalate"
    ]

    #for str in arr
    #  cmd = str.split " - "
    #  cmds.push "`#{cmd[0]}` - #{cmd[1]}"

    usermsg = "```" + arr.join("\n") + "```"
    if config.replyInPrivate and msg.message?.user?.name?
      msg.reply 'replied to you in private!'
      robot.send {room: msg.message?.user?.name}, usermsg
    else
      msg.reply usermsg

  robot.respond /auth add (["'\w: -_]+) to @?([^\s]+)$/i, (msg) ->
    return unless isAuthorized robot, msg, 'admin'
    return addAuth robot, msg

  robot.respond /auth who(?:ami|\sis|\sam)?\s?@?([^\s]+)?$/i, (msg) ->
    return authWho robot, msg

  robot.respond /auth remove (["'\w: -_]+) from @?([^\s]+)/i, (msg) ->
    return unless isAuthorized robot, msg, 'admin'
    return removeAuth robot, msg

  robot.respond /auth list roles for @?([^\s]+)$/i, (msg) ->
    return unless isAuthorized robot, msg, 'admin'
    return listAuthRolesForUser robot, msg

  robot.respond /auth list users with (["'\w: -_]+)$/i, (msg) ->
    return unless isAuthorized robot, msg, 'admin'
    return listAuthUsersWithRole robot, msg

  robot.respond /auth list roles$/i, (msg) ->
    return unless isAuthorized robot, msg, 'admin'
    return listAuthRoles robot, msg

  robot.respond /auth (?:2fa|duo2fa)$/i, (msg) ->
    #return unless isAuthorized robot, msg, '2fa'
    return duo2faAuth robot, msg
