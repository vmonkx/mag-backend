const { forwardTo } = require("prisma-binding");
const { hasPermission } = require("../utils");

const Query = {
  items: forwardTo("db"),
  item: forwardTo("db"),
  itemsConnection: forwardTo("db"),

  me(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId },
      },
      info
    );
  },

  async users(parent, args, ctx, info) {
    //check logged
    if (!ctx.request.userId) {
      throw new Error("You must be logged in!");
    }
    //check user permisson
    hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);
    // if they do, query all the users
    return ctx.db.query.users({}, info);
  },

  async order(parent, args, ctx, info) {
    //make sure they are logged in
    if (!ctx.request.userId) {
      throw new Error("You arent logged in!");
    }
    // query the current order
    const order = await ctx.db.query.order(
      {
        where: { id: args.id },
      },
      info
    );
    // check if the the permissions to see this order
    const ownsOrder = order.user.id === ctx.request.userId;
    const hasPermissionToSeeOrder = ctx.request.user.permissions.includes(
      "ADMIN"
    );

    if (!ownsOrder || !hasPermissionToSeeOrder) {
      throw new Error("You cant see this buddd");
    }

    return order;
    // return the order
  },

  async orders(parent, args, ctx, info) {
    const { userId } = ctx.request;

    if (!userId) {
      throw new Error("You must be signed in!");
    }

    return ctx.db.query.orders(
      {
        where: {
          user: { id: userId },
        },
      },
      info
    );
  },
  /* async items(parent, args, ctx, info) {
    const items = await ctx.db.query.items();

    return items;
  }, */
};

module.exports = Query;
