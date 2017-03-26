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


grant2fa = (robot, msg, un) ->
  expires = moment(auth_data.duo2fa[un])
  if expires.valueOf() > Date.now()
    return msg.reply "#{modulename}: 2fa already granted.  Expires in #{expires.fromNow()}`."

  auth_data.duo2fa[un] = new moment().add(1,'hours')
  writeData()

  expires = auth_data.duo2fa[un].format(timefmt)
  logmsg = "#{modulename}: #{un} granted 2fa until #{expires}"
  robot.logger.info logmsg

  return msg.reply "#{modulename}: 2fa granted until `#{expires}`."


expirationWorker = ->
  expireEntries()
  setTimeout expirationWorker, svcQueueIntervalMs


expireEntries = ->
  removequeue = []
  for un, expiresdt of auth_data.duo2fa when moment(expiresdt).valueOf() < Date.now()
    usermsg = "#{modulename}: #{un} 2fa grant has expired"
    removequeue.push un
    robotRef.send { room: un }, usermsg
    robotRef.logger.info usermsg

  if removequeue.length > 0
    while removequeue.length > 0
      delete auth_data.duo2fa[removequeue.shift()]
      usermsg = "#{modulename}: #{un} 2fa grant has expired"
      robotRef.send { room: un }, usermsg
      robotRef.logger.info usermsg
    writeData()


addAuth = (robot, msg) ->
  who = msg.message.user.name
  un = msg.match[2].trim()
  if un.toLowerCase() is 'i' then un = who

  newRole = msg.match[1].trim().toLowerCase()

  user = robot.brain.userForName(un)
  return msg.reply "#{un} does not exist" unless user?
  user.roles or= []

  if newRole in user.roles
    return msg.reply "#{un} already has the '#{newRole}' role."

  if newRole is 'admin'
    errmsg = "Sorry, the 'admin' role can only be defined in the " +
      "HUBOT_AUTH_ADMIN env variable."
    return msg.reply errmsg

  myRoles = msg.message.user.roles or []
  user.roles.push(newRole)
  #writeData()

  logmsg = "#{modulename}: #{who} added '#{newRole}' " +
    "role to '#{un}' user"
  robot.logger.info logmsg

  return msg.reply "OK, #{un} has the '#{newRole}' role."


authWho = (robot, msg) ->
  who = msg.message.user.name
  if msg.match[1]?
    un = msg.match[1].trim()
    if un.toLowerCase() is 'i' then un = who
    user = robot.brain.userForName(un)
    return msg.reply "#{un} does not exist" unless user?
  else
    user = msg.message.user

  return msg.send "#{user.name} is #{user.id}"


removeAuth = (robot, msg) ->
  who = msg.message.user.name
  un = msg.match[2].trim()
  if un.toLowerCase() is 'i' then un = who

  newRole = msg.match[1].trim().toLowerCase()

  user = robot.brain.userForName(un)
  return msg.reply "#{un} does not exist" unless user?
  user.roles or= []

  if newRole is 'admin'
    errmsg = "Sorry, the 'admin' role can only be removed from the " +
      "HUBOT_AUTH_ADMIN env variable."
    return msg.reply errmsg

  myRoles = msg.message.user.roles or []
  user.roles = (role for role in user.roles when role isnt newRole)
  #writeData()

  logmsg = "#{modulename}: #{who} removed '#{newRole}' " +
    "role from '#{un}' user"
  robot.logger.info logmsg

  return msg.reply "OK, #{un} doesn't have the '#{newRole}' role."


listAuthRolesForUser = (robot, msg) ->
  who = msg.message.user.name
  un = msg.match[1].trim()
  if un.toLowerCase() is 'i' then un = who
  user = robot.brain.userForName(un)
  return msg.reply "#{un} does not exist" unless user?
  userRoles = robot.auth.userRoles(user)

  if userRoles.length == 0
    return msg.reply "#{un} has no roles."

  return msg.reply "#{un} has the following roles: #{userRoles.join(', ')}."


listAuthUsersWithRole = (robot, msg) ->
  role = msg.match[1]
  userNames = robot.auth.usersWithRole(role) if role?

  if userNames.length > 0
    return msg.reply "Users with `#{role}` role: `#{userNames.join('`, `')}`"

  return msg.reply "No one has `#{role}` role."


listAuthRoles = (robot, msg) ->
  roles = []

  for i, user of robot.brain.data.users when user.roles
    roles.push role for role in user.roles when role not in roles
  if roles.length > 0
    return msg.reply "The following roles are available: #{roles.join(', ')}"

  return msg.reply "No roles to list."


duo2faAuth = (robot, msg) ->
  who = msg.message.user.name

  if auth_data.duo2fa[who]
    expires = moment(auth_data.duo2fa[who])
    if expires.valueOf() > Date.now()
      return msg.reply "#{modulename}: 2fa already granted.  Expires in #{expires.fromNow()}`."

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
        msg.reply "#{modulename}: duo reports: `#{res.status_msg}`"
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
      console.log("#{modulename}: unable to read #{data_file}: ", error)

  if config.admin_list?
    admins = config.admin_list.split ','
  else
    admins = []

  class Auth
    isAdmin: (user) ->
      user.id.toString() in admins

    is2fa: (user) ->
      return false unless user.name of auth_data.duo2fa
      return false unless moment().isBefore(auth_data.duo2fa[user.name])
      return true

    hasRole: (user, roles) ->
      userRoles = @userRoles(user)
      if userRoles?
        roles = [roles] if typeof roles is 'string'
        for role in roles
          return true if role in userRoles
      return false

    usersWithRole: (role) ->
      users = []
      for own key, user of robot.brain.data.users
        if @hasRole(user, role)
          users.push(user.name)
      users

    userRoles: (user) ->
      roles = []
      if user? and robot.auth.isAdmin user
        roles.push('admin')
      if user.roles?
        roles = roles.concat user.roles
      roles

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
