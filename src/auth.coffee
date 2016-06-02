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

config =
  admin_list: process.env.HUBOT_AUTH_ADMIN

replyInPrivate = process.env.HUBOT_HELP_REPLY_IN_PRIVATE

isAuthorized = (robot, msg) ->
  return true if robot.auth.isAdmin(msg.envelope.user)
  msg.send {room: msg.message.user.name}, "Only admins allowed to make auth changes."
  return false

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
    name = msg.match[2].trim()
    if name.toLowerCase() is 'i' then name = msg.message.user.name

    return unless isAuthorized robot, msg

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
    name = msg.match[2].trim()
    if name.toLowerCase() is 'i' then name = msg.message.user.name

    unless robot.auth.isAdmin msg.message.user
      return msg.reply "Sorry, only admins can remove roles."

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
    name = msg.match[1].trim()
    if name.toLowerCase() is 'i' then name = msg.message.user.name
    user = robot.brain.userForName(name)
    return msg.reply "#{name} does not exist" unless user?
    userRoles = robot.auth.userRoles(user)

    if userRoles.length == 0
      return msg.reply "#{name} has no roles."

    return msg.reply "#{name} has the following roles: #{userRoles.join(', ')}."


  robot.respond /auth list users with (["'\w: -_]+)$/i, (msg) ->
    role = msg.match[1]
    userNames = robot.auth.usersWithRole(role) if role?

    if userNames.length > 0
      return msg.reply "The following people have the '#{role}' role: #{userNames.join(', ')}"

    return msg.reply "There are no people that have the '#{role}' role."


  robot.respond /auth list roles$/i, (msg) ->
    roles = []
    unless robot.auth.isAdmin msg.message.user
      return msg.reply "Sorry, only admins can list assigned roles."

    for i, user of robot.brain.data.users when user.roles
      roles.push role for role in user.roles when role not in roles
    if roles.length > 0
      return msg.reply "The following roles are available: #{roles.join(', ')}"

    return msg.reply "No roles to list."
