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

moment = require 'moment'

config =
  admin_list: process.env.HUBOT_AUTH_ADMIN
  duo: false

if process.env.HUBOT_AUTH_DUO_IKEY and process.env.HUBOT_AUTH_DUO_SKEY and process.env.HUBOT_AUTH_DUO_HOST
  duo_api = require 'duo_api'
  config['duo'] = true
  config['duo_ikey'] = process.env.HUBOT_AUTH_DUO_IKEY
  config['duo_skey'] = process.env.HUBOT_AUTH_DUO_SKEY
  config['duo_host'] = process.env.HUBOT_AUTH_DUO_HOST
  duoclient = new duo_api.Client(parsed.ikey, parsed.skey, parsed.host);
  duoclient.jsonApiCall 'GET', '/auth/v2/check', {}, (res) ->
    unless res.stat is 'OK'
      console.error 'duo api check failed: '+ res.message
      process.exit(1)

sudoed = {}

replyInPrivate = process.env.HUBOT_HELP_REPLY_IN_PRIVATE


isAuthorized = (robot, msg, roles=['admin']) ->
  roles = [roles] if typeof roles is 'string'
  return true if robot.auth.isAdmin(msg.envelope.user)
  return true if robot.auth.hasRole(msg.envelope.user,roles)
  msg.send {room: msg.message.user.name}, "Only #{roles.split ', '} allowed this command."
  return false

grantSudo = (msg, user) ->
  if sudoed[user] and moment().isBefore(sudoed[user])
    return msg.reply "Sudo already granted.  Expires `#{sudoed[user].format('YYYY-MM-DD HH:mm:ss ZZ')}`."

  if ! sudoed[user] or moment().isAfter(sudoed[user])
    sudoed[user] = new moment().add(1,'hours')
    return msg.reply "Sudo granted.  Expires `#{sudoed[user].format('YYYY-MM-DD HH:mm:ss ZZ')}`."


module.exports = (robot) ->

  unless config.admin_list?
    robot.logger.warning 'The HUBOT_AUTH_ADMIN environment variable not set'

  if config.admin_list?
    admins = config.admin_list.split ','
  else
    admins = []

  class Auth
    isAdmin: (user) ->
      user.id.toString() in admins

    isSudo: (user) ->
      return false unless user.name of sudoed
      return false unless moment().isBefore(sudoed[user.name])
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


  robot.respond /auth help$/, (msg) ->
    cmds = []
    arr = [
      "auth add <role> to <user> - role assignment"
      "auth remove <role> from <user> - remove role from user"
      "auth list roles for <user> - list roles"
      "auth list users with <role> - list users"
      "auth list roles - list roles"
      "auth sudo - escalate"
    ]

    for str in arr
      cmd = str.split " - "
      cmds.push "`#{cmd[0]}` - #{cmd[1]}"

    if replyInPrivate and msg.message?.user?.name?
      msg.reply 'replied to you in private!'
      robot.send {room: msg.message?.user?.name}, cmds.join "\n"
    else
      msg.reply cmds.join "\n"

  robot.respond /auth add (["'\w: -_]+) to @?([^\s]+)$/i, (msg) ->
    return unless isAuthorized robot, msg

    name = msg.match[2].trim()
    if name.toLowerCase() is 'i' then name = msg.message.user.name

    newRole = msg.match[1].trim().toLowerCase()

    user = robot.brain.userForName(name)
    return msg.reply "#{name} does not exist" unless user?
    user.roles or= []

    if newRole in user.roles
      return msg.reply "#{name} already has the '#{newRole}' role."

    if newRole is 'admin'
      return msg.reply "Sorry, the 'admin' role can only be defined in the HUBOT_AUTH_ADMIN env variable."

    myRoles = msg.message.user.roles or []
    user.roles.push(newRole)
    msg.reply "OK, #{name} has the '#{newRole}' role."

  robot.respond /auth who(?:ami|\sis|\sam)?\s?@?([^\s]+)?$/i, (msg) ->
    if msg.match[1]?
      name = msg.match[1].trim()
      if name.toLowerCase() is 'i' then name = msg.message.user.name
      user = robot.brain.userForName(name)
      return msg.reply "#{name} does not exist" unless user?
    else
      user = msg.message.user

    return msg.send "#{user.name} is #{user.id}"

  robot.respond /auth remove (["'\w: -_]+) from @?([^\s]+)/i, (msg) ->
    return unless isAuthorized robot, msg

    name = msg.match[2].trim()
    if name.toLowerCase() is 'i' then name = msg.message.user.name

    newRole = msg.match[1].trim().toLowerCase()

    user = robot.brain.userForName(name)
    return msg.reply "#{name} does not exist" unless user?
    user.roles or= []

    if newRole is 'admin'
      return msg.reply "Sorry, the 'admin' role can only be removed from the HUBOT_AUTH_ADMIN env variable."

    myRoles = msg.message.user.roles or []
    user.roles = (role for role in user.roles when role isnt newRole)
    return msg.reply "OK, #{name} doesn't have the '#{newRole}' role."


  robot.respond /auth list roles for @?([^\s]+)$/i, (msg) ->
    return unless isAuthorized robot, msg

    name = msg.match[1].trim()
    if name.toLowerCase() is 'i' then name = msg.message.user.name
    user = robot.brain.userForName(name)
    return msg.reply "#{name} does not exist" unless user?
    userRoles = robot.auth.userRoles(user)

    if userRoles.length == 0
      return msg.reply "#{name} has no roles."

    return msg.reply "#{name} has the following roles: #{userRoles.join(', ')}."


  robot.respond /auth list users with (["'\w: -_]+)$/i, (msg) ->
    return unless isAuthorized robot, msg

    role = msg.match[1]
    userNames = robot.auth.usersWithRole(role) if role?

    if userNames.length > 0
      return msg.reply "Users with `#{role}` role: `#{userNames.join('`, `')}`"

    return msg.reply "No one has `#{role}` role."


  robot.respond /auth list roles$/i, (msg) ->
    return unless isAuthorized robot, msg

    roles = []

    for i, user of robot.brain.data.users when user.roles
      roles.push role for role in user.roles when role not in roles
    if roles.length > 0
      return msg.reply "The following roles are available: #{roles.join(', ')}"

    return msg.reply "No roles to list."

  robot.respond /auth sudo$/i, (msg) ->
    return unless isAuthorized robot, msg, 'sudo'

    user = msg.message.user.name

    if config.duo
      duoclient.jsonApiCall 'POST', '/auth/v2/check', { username: user, factor: 'push', device: 'auto' }, (res) ->
        unless res.result is "allow"
          return msg.reply "duo api auth failed: #{res.status_msg}"
        msg.reply "duo api auth success: `#{res.status}`\n```\n#{res.status_msg}\n```"
        return grantSudo(msg, user)

    return grantSudo(msg, user) unless config.duo
