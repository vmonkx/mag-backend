const bycript = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");
const { promisify } = require("util");
const { hasPermission } = require("../utils");

const { makeANiceEmail, transport } = require("../mail");

const stripe = require("../stripe");

const Mutations = {
  async createItem(parent, args, ctx, info) {
    // TODO: Check if they are logged in

    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that!");
    }

    const item = await ctx.db.mutation.createItem(
      {
        data: {
          // this is how to create a relationship beetwen item and user
          user: {
            connect: {
              id: ctx.request.userId,
            },
          },
          ...args,
        },
      },
      info
    );

    console.log(item);

    return item;
  },

  updateItem(parent, args, ctx, info) {
    // first take a copy of the updates
    const updates = { ...args };

    // remove the ID from the updates
    delete updates.id;
    // run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id,
        },
      },
      info
    );
  },

  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{id title user {id}}`);
    // 2. Check if they own that item, or have the permissions
    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some((permission) =>
      ["ADMIN", "ITEMDELETE"].includes(permission)
    );
    // TODO
    if (!ownsItem && hasPermissions) {
      throw new Error("You arent allowed");
    }
    // 3. Delete it!
    return ctx.db.mutation.deleteItem({ where }, info);
  },

  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();
    // hash their password
    const password = await bycript.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ["USER"] },
        },
      },
      info
    );
    // create the JWT token for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // We set the jwt as a cookie on the response
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year cookie
    });

    // Finalllllly we return the user to the browser
    return user;
  },

  async signin(parent, { email, password }, ctx, info) {
    const user = await ctx.db.query.user({ where: { email } });
    // check user
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }
    //check password
    const valid = await bycript.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid login or password");
    }
    //generate token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);

    //set cookie
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365,
    });
    //return user
    return user;
  },

  signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return { message: "Goodbye!" };
  },

  async requestReset(parent, args, ctx, info) {
    //check this is real user
    const user = await ctx.db.query.user({ where: { email: args.email } });

    if (!user) {
      throw new Error(`No such user found for email ${args.email}`);
    }
    //set reset token
    const randomBytesPromiseifed = promisify(randomBytes);
    const resetToken = (await randomBytesPromiseifed(20)).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; //1 hour from now
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry },
    });

    //email them that reset token
    const mailRes = await transport.sendMail({
      from: "wes@wesbos.com",
      to: user.email,
      subject: "Your Password Reset Token",
      html: makeANiceEmail(`Your Password Reset Token is here!
      \n\n
      <a href="${
        process.env.FRONTEND_URL
      }/reset?resetToken=${resetToken}">Click Here to Reset</a>`),
    });
    // return Message
    return { message: "Thanks" };
  },

  async resetPassword(parent, args, ctx, info) {
    //check if password match
    if (args.password !== args.confirmPassword) {
      throw new Error("Yo Password dont match!");
    }
    //check if legit reset token
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000,
      },
    });

    //check if its expired
    if (!user) {
      throw new Error("this token is either invalid or expired");
    }
    //check their new password
    const password = await bycript.hash(args.password, 10);
    //save new password
    const upadateUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });
    //generate JWT
    const token = jwt.sign({ userId: upadateUser.id }, process.env.APP_SECRET);
    //set the JWT coockie
    ctx.response.cookie("token", token, {
      maxAge: 1000 * 60 * 60 * 24 * 365,
      httpOnly: true,
    });
    //return the new user
    return upadateUser;
  },

  async updatePermissions(parent, args, ctx, info) {
    // check logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in!");
    }
    //query current user
    const currentUser = await ctx.db.query.user(
      {
        where: {
          id: ctx.request.userId,
        },
      },
      info
    );
    //check if they permissions to do this
    hasPermission(currentUser, ["ADMIN", "PERMISSIONUPDATE"]);
    // update permissions
    return ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions,
          },
        },
        where: {
          id: args.userId,
        },
      },
      info
    );
  },

  async addToCart(parent, args, ctx, info) {
    //Make sure they are signed in
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed");
    }
    // query the users current cart
    const [existingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id },
      },
    });

    // check if that item is already in ther cart
    if (existingCartItem) {
      console.log("this item is already in cart");
      return ctx.db.mutation.updateCartItem(
        {
          where: { id: existingCartItem.id },
          data: { quantity: existingCartItem.quantity + 1 },
        },
        info
      );
    }
    // if its not, create fresh cartItem
    return ctx.db.mutation.createCartItem(
      {
        data: {
          user: {
            connect: { id: userId },
          },
          item: {
            connect: { id: args.id },
          },
        },
      },
      info
    );
  },

  async removeFromCart(parent, args, ctx, info) {
    //find cart item
    const cartItem = await ctx.db.query.cartItem(
      {
        where: {
          id: args.id,
        },
      },
      `{id, user {id}}`
    );

    // make sure we found an item
    if (!cartItem) {
      throw new Error("No cartItem found!");
    }

    // make sure they own that cart item
    if (cartItem.user.id !== ctx.request.userId) {
      throw new Error("Cheatin huhhhh");
    }

    // delete that cart item
    return ctx.db.mutation.deleteCartItem(
      {
        where: {
          id: args.id,
        },
      },
      info
    );
  },

  async createOrder(parent, args, ctx, info) {
    // query the current user and make sure they are signed in
    const { userId } = ctx.request;

    if (!userId)
      throw new Error("You must be signed in to complete this order");

    const user = await ctx.db.query.user(
      { where: { id: userId } },
      `{
        id 
        name 
        email 
        cart {
          id
          quantity 
          item {title price id description image largeImage}
      }}`
    );
    // recalculate the total for the price
    const amount = user.cart.reduce(
      (total, cartItem) => total + cartItem.item.price * cartItem.quantity,
      0
    );

    // create stripe charge(turn token into $$$)
    const charge = await stripe.charges.create({
      amount: amount,
      currency: "USD",
      source: args.token,
    });

    // convert cartItems to OrderItems
    const orderItems = user.cart.map((cartItem) => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: { connect: { id: userId } },
      };
      delete orderItem.id;
      return orderItem;
    });

    // create Order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        items: { create: orderItems },
        user: { connect: { id: userId } },
      },
    });
    // Clean up - clear the user cart, delete cartItems
    const cartItemIds = user.cart.map((cartItem) => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds,
      },
    });
    // return the Order to the client
    return order;
  },
};

module.exports = Mutations;
