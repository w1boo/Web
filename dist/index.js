// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// server/storage.ts
import session2 from "express-session";
import createMemoryStore from "memorystore";

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  try {
    const [hashed, salt] = stored.split(".");
    if (!hashed || !salt) {
      console.log("Invalid stored password format");
      return false;
    }
    const hashedBuf = Buffer.from(hashed, "hex");
    const suppliedBuf = await scryptAsync(supplied, salt, 64);
    if (hashedBuf.length !== suppliedBuf.length) {
      console.log(`Buffer length mismatch: ${hashedBuf.length} vs ${suppliedBuf.length}`);
      return false;
    }
    return timingSafeEqual(hashedBuf, suppliedBuf);
  } catch (error) {
    console.error("Password comparison error:", error);
    return false;
  }
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "meraki-marketplace-secret",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      maxAge: 24 * 60 * 60 * 1e3,
      // 24 hours
      secure: process.env.NODE_ENV === "production"
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      const user = await storage.getUserByUsername(username);
      if (!user || !await comparePasswords(password, user.password)) {
        return done(null, false);
      }
      const isAdmin = username === "admin";
      return done(null, { ...user, isAdmin });
    })
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    const user = await storage.getUser(id);
    done(null, user);
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).send("Username already exists");
      }
      const user = await storage.createUser({
        ...req.body,
        password: await hashPassword(req.body.password)
      });
      req.login(user, (err) => {
        if (err) return next(err);
        res.status(201).json(user);
      });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/login", passport.authenticate("local"), (req, res) => {
    res.status(200).json(req.user);
  });
  app2.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    res.json(req.user);
  });
}

// server/storage.ts
var MemoryStore = createMemoryStore(session2);
var MemStorage = class {
  users;
  products;
  categories;
  transactions;
  tradeOffers;
  messages;
  conversations;
  deposits;
  withdrawals;
  currentUserId;
  currentProductId;
  currentCategoryId;
  currentTransactionId;
  currentTradeOfferId;
  currentMessageId;
  currentConversationId;
  currentDepositId;
  currentWithdrawalId;
  sessionStore;
  // Changed from session.SessionStore to any
  constructor() {
    this.users = /* @__PURE__ */ new Map();
    this.products = /* @__PURE__ */ new Map();
    this.categories = /* @__PURE__ */ new Map();
    this.transactions = /* @__PURE__ */ new Map();
    this.tradeOffers = /* @__PURE__ */ new Map();
    this.messages = /* @__PURE__ */ new Map();
    this.conversations = /* @__PURE__ */ new Map();
    this.deposits = /* @__PURE__ */ new Map();
    this.withdrawals = /* @__PURE__ */ new Map();
    this.currentUserId = 1;
    this.currentProductId = 1;
    this.currentCategoryId = 1;
    this.currentTransactionId = 1;
    this.currentTradeOfferId = 1;
    this.currentMessageId = 1;
    this.currentConversationId = 1;
    this.currentDepositId = 1;
    this.currentWithdrawalId = 1;
    this.sessionStore = new MemoryStore({
      checkPeriod: 864e5
    });
    this.seedCategories();
    this.seedAdminUser().catch((err) => {
      console.error("Failed to seed admin user:", err);
    });
  }
  // Create an admin user for testing
  async seedAdminUser() {
    try {
      const adminPasswordHash = await hashPassword("admin123");
      const adminUser = {
        id: this.currentUserId++,
        username: "admin",
        password: adminPasswordHash,
        firstName: "Admin",
        lastName: "User",
        email: "admin@example.com",
        avatar: null,
        location: null,
        balance: 1e3,
        // Give admin some balance to work with
        escrowBalance: 0,
        isAdmin: true,
        createdAt: /* @__PURE__ */ new Date()
      };
      this.users.set(adminUser.id, adminUser);
      console.log("Admin user created with ID:", adminUser.id);
      console.log("Admin password hash:", adminPasswordHash);
    } catch (error) {
      console.error("Error creating admin user:", error);
    }
  }
  // Initialize basic categories
  seedCategories() {
    const categories = [
      { name: "Electronics", icon: "ri-computer-line", color: "secondary" },
      { name: "Fashion", icon: "ri-t-shirt-line", color: "accent" },
      { name: "Books & Media", icon: "ri-book-open-line", color: "primary" }
    ];
    categories.forEach((category) => {
      const id = this.currentCategoryId++;
      this.categories.set(id, {
        id,
        name: category.name,
        icon: category.icon,
        color: category.color
      });
    });
  }
  // User methods
  async getUser(id) {
    return this.users.get(id);
  }
  async getUserByUsername(username) {
    return Array.from(this.users.values()).find(
      (user) => user.username === username
    );
  }
  async getUserByEmail(email) {
    if (!email) return void 0;
    return Array.from(this.users.values()).find((user) => user.email === email);
  }
  async createUser(insertUser) {
    if (insertUser.email) {
      const existingUser = await this.getUserByEmail(insertUser.email);
      if (existingUser) {
        throw new Error("Email already exists");
      }
    }
    const id = this.currentUserId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const user = {
      id,
      username: insertUser.username,
      password: insertUser.password,
      firstName: insertUser.firstName || null,
      lastName: insertUser.lastName || null,
      email: insertUser.email || null,
      avatar: insertUser.avatar || null,
      location: insertUser.location || null,
      balance: 0,
      escrowBalance: 0,
      isAdmin: insertUser.isAdmin || false,
      createdAt: timestamp2
    };
    this.users.set(id, user);
    return user;
  }
  async updateUser(id, updates) {
    const user = await this.getUser(id);
    if (!user) return void 0;
    const updatedUser = { ...user, ...updates };
    this.users.set(id, updatedUser);
    return updatedUser;
  }
  // Product methods
  async createProduct(product) {
    const id = this.currentProductId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const newProduct = {
      id,
      title: product.title,
      description: product.description,
      price: product.price || null,
      images: product.images,
      categoryId: product.categoryId || null,
      sellerId: product.sellerId,
      location: product.location || null,
      allowTrade: product.allowTrade || false,
      allowBuy: product.allowBuy || false,
      tradeValue: product.tradeValue || null,
      status: product.status || "active",
      createdAt: timestamp2
    };
    this.products.set(id, newProduct);
    return newProduct;
  }
  async getProduct(id) {
    return this.products.get(id);
  }
  async getProductsByCategory(categoryId) {
    console.log("Filtering products by categoryId:", categoryId);
    const allProducts = Array.from(this.products.values());
    console.log("All products:", JSON.stringify(allProducts));
    return allProducts.filter((product) => {
      console.log(`Product ${product.id} categoryId:`, product.categoryId, "Comparing with:", categoryId, "Result:", product.categoryId === categoryId);
      return product.categoryId === categoryId;
    });
  }
  async getProductsBySeller(sellerId) {
    return Array.from(this.products.values()).filter((product) => product.sellerId === sellerId);
  }
  async getProductsByUser(userId) {
    return Array.from(this.products.values()).filter((p) => p.sellerId === userId);
  }
  async getRecentProducts(limit) {
    return Array.from(this.products.values()).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()).slice(0, limit);
  }
  async updateProduct(id, updates) {
    const product = await this.getProduct(id);
    if (!product) return void 0;
    const updatedProduct = { ...product, ...updates };
    this.products.set(id, updatedProduct);
    return updatedProduct;
  }
  // Category methods
  async createCategory(category) {
    const id = this.currentCategoryId++;
    const newCategory = { ...category, id };
    this.categories.set(id, newCategory);
    return newCategory;
  }
  async getCategories() {
    return Array.from(this.categories.values());
  }
  async getCategory(id) {
    return this.categories.get(id);
  }
  // Trade Offer methods
  async createTradeOffer(tradeOffer) {
    const id = this.currentTradeOfferId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const newTradeOffer = {
      id,
      buyerId: tradeOffer.buyerId,
      sellerId: tradeOffer.sellerId,
      productId: tradeOffer.productId,
      offerValue: tradeOffer.offerValue,
      status: tradeOffer.status || "pending",
      buyerConfirmed: tradeOffer.buyerConfirmed || false,
      sellerConfirmed: tradeOffer.sellerConfirmed || false,
      relatedMessageId: tradeOffer.relatedMessageId || null,
      offerItemName: tradeOffer.offerItemName || null,
      offerItemDescription: tradeOffer.offerItemDescription || null,
      offerItemImages: tradeOffer.offerItemImages || [],
      createdAt: timestamp2,
      updatedAt: timestamp2
    };
    this.tradeOffers.set(id, newTradeOffer);
    return newTradeOffer;
  }
  async getTradeOffer(id) {
    return this.tradeOffers.get(id);
  }
  async getUserTradeOffers(userId) {
    return Array.from(this.tradeOffers.values()).filter(
      (tradeOffer) => tradeOffer.buyerId === userId || tradeOffer.sellerId === userId
    ).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  async getPendingTradeOffers(userId) {
    return Array.from(this.tradeOffers.values()).filter(
      (tradeOffer) => (tradeOffer.buyerId === userId || tradeOffer.sellerId === userId) && tradeOffer.status === "pending"
    ).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  async updateTradeOffer(id, updates) {
    const tradeOffer = await this.getTradeOffer(id);
    if (!tradeOffer) return void 0;
    const updatedTradeOffer = {
      ...tradeOffer,
      ...updates,
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.tradeOffers.set(id, updatedTradeOffer);
    return updatedTradeOffer;
  }
  // Transaction methods
  async createTransaction(transaction) {
    const id = this.currentTransactionId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const newTransaction = {
      id,
      transactionId: transaction.transactionId,
      productId: transaction.productId,
      buyerId: transaction.buyerId,
      sellerId: transaction.sellerId,
      amount: transaction.amount,
      platformFee: transaction.platformFee,
      shipping: transaction.shipping || null,
      status: transaction.status,
      type: transaction.type,
      tradeDetails: transaction.tradeDetails || null,
      timeline: transaction.timeline || [],
      createdAt: timestamp2,
      updatedAt: timestamp2
    };
    this.transactions.set(id, newTransaction);
    return newTransaction;
  }
  async getTransaction(id) {
    return this.transactions.get(id);
  }
  async getTransactionByTransactionId(transactionId) {
    return Array.from(this.transactions.values()).find((transaction) => transaction.transactionId === transactionId);
  }
  async getUserTransactions(userId) {
    return Array.from(this.transactions.values()).filter(
      (transaction) => transaction.buyerId === userId || transaction.sellerId === userId
    ).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  async updateTransaction(id, updates) {
    const transaction = await this.getTransaction(id);
    if (!transaction) return void 0;
    const updatedTransaction = {
      ...transaction,
      ...updates,
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.transactions.set(id, updatedTransaction);
    return updatedTransaction;
  }
  // Message methods
  async createMessage(message) {
    const id = this.currentMessageId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const newMessage = {
      id,
      senderId: message.senderId,
      receiverId: message.receiverId,
      content: message.content,
      images: message.images || null,
      isRead: false,
      isTrade: message.isTrade || false,
      productId: message.productId || null,
      tradeOfferId: message.tradeOfferId || null,
      tradeDetails: message.tradeDetails || null,
      tradeConfirmedBuyer: message.tradeConfirmedBuyer || false,
      tradeConfirmedSeller: message.tradeConfirmedSeller || false,
      createdAt: timestamp2
    };
    this.messages.set(id, newMessage);
    return newMessage;
  }
  async getMessages(conversationId) {
    const conversation = await this.getConversation(conversationId);
    if (!conversation) return [];
    const user1Id = conversation.user1Id;
    const user2Id = conversation.user2Id;
    return Array.from(this.messages.values()).filter(
      (message) => message.senderId === user1Id && message.receiverId === user2Id || message.senderId === user2Id && message.receiverId === user1Id
    ).sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  }
  async markMessageAsRead(id) {
    const message = this.messages.get(id);
    if (!message) return void 0;
    const updatedMessage = { ...message, isRead: true };
    this.messages.set(id, updatedMessage);
    return updatedMessage;
  }
  async getMessage(id) {
    return this.messages.get(id);
  }
  async updateMessage(id, updates) {
    const message = this.messages.get(id);
    if (!message) return void 0;
    const updatedMessage = { ...message, ...updates };
    this.messages.set(id, updatedMessage);
    return updatedMessage;
  }
  // Conversation methods
  async createConversation(conversation) {
    const id = this.currentConversationId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const newConversation = {
      id,
      user1Id: conversation.user1Id,
      user2Id: conversation.user2Id,
      lastMessageId: conversation.lastMessageId || null,
      updatedAt: timestamp2
    };
    this.conversations.set(id, newConversation);
    return newConversation;
  }
  async getConversation(id) {
    return this.conversations.get(id);
  }
  async getUserConversations(userId) {
    return Array.from(this.conversations.values()).filter(
      (conversation) => conversation.user1Id === userId || conversation.user2Id === userId
    ).sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
  }
  async getConversationByUsers(user1Id, user2Id) {
    console.log(`Looking for conversation between users ${user1Id} and ${user2Id}`);
    const u1 = Number(user1Id);
    const u2 = Number(user2Id);
    if (isNaN(u1) || isNaN(u2)) {
      console.error(`Invalid user IDs: ${user1Id}, ${user2Id}`);
      return void 0;
    }
    const allConversations = Array.from(this.conversations.values());
    console.log(`Total conversations: ${allConversations.length}`);
    const conversation = allConversations.find(
      (c) => c.user1Id === u1 && c.user2Id === u2 || c.user1Id === u2 && c.user2Id === u1
    );
    if (conversation) {
      console.log(`Found conversation: ${JSON.stringify(conversation)}`);
    } else {
      console.log(`No conversation found between users ${u1} and ${u2}`);
    }
    return conversation;
  }
  async updateConversation(id, updates) {
    const conversation = await this.getConversation(id);
    if (!conversation) return void 0;
    const updatedConversation = {
      ...conversation,
      ...updates,
      updatedAt: /* @__PURE__ */ new Date()
    };
    this.conversations.set(id, updatedConversation);
    return updatedConversation;
  }
  // Financial methods
  async createDeposit(deposit) {
    const id = this.currentDepositId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const newDeposit = {
      ...deposit,
      id,
      createdAt: timestamp2
    };
    this.deposits.set(id, newDeposit);
    return newDeposit;
  }
  async getDeposit(id) {
    return this.deposits.get(id);
  }
  async getUserDeposits(userId) {
    return Array.from(this.deposits.values()).filter((deposit) => deposit.userId === userId).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  async updateDeposit(id, updates) {
    const deposit = this.deposits.get(id);
    if (!deposit) return void 0;
    const updatedDeposit = { ...deposit, ...updates };
    this.deposits.set(id, updatedDeposit);
    return updatedDeposit;
  }
  async createWithdrawal(withdrawal) {
    const id = this.currentWithdrawalId++;
    const timestamp2 = /* @__PURE__ */ new Date();
    const newWithdrawal = {
      ...withdrawal,
      id,
      createdAt: timestamp2
    };
    this.withdrawals.set(id, newWithdrawal);
    return newWithdrawal;
  }
  async getUserWithdrawals(userId) {
    return Array.from(this.withdrawals.values()).filter((withdrawal) => withdrawal.userId === userId).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }
  async updateWithdrawal(id, updates) {
    const withdrawal = this.withdrawals.get(id);
    if (!withdrawal) return void 0;
    const updatedWithdrawal = { ...withdrawal, ...updates };
    this.withdrawals.set(id, updatedWithdrawal);
    return updatedWithdrawal;
  }
};
var storage = new MemStorage();

// server/routes.ts
import { z } from "zod";

// shared/schema.ts
import { pgTable, text, serial, integer, boolean, timestamp, doublePrecision, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  firstName: text("first_name"),
  lastName: text("last_name"),
  email: text("email"),
  avatar: text("avatar"),
  location: text("location"),
  balance: doublePrecision("balance").default(0).notNull(),
  escrowBalance: doublePrecision("escrow_balance").default(0).notNull(),
  isAdmin: boolean("is_admin").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var productCategories = pgTable("product_categories", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  icon: text("icon").notNull(),
  color: text("color").notNull()
});
var products = pgTable("products", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  price: doublePrecision("price"),
  images: text("images").array().notNull(),
  categoryId: integer("category_id").references(() => productCategories.id),
  sellerId: integer("seller_id").references(() => users.id).notNull(),
  location: text("location"),
  allowTrade: boolean("allow_trade").default(true).notNull(),
  allowBuy: boolean("allow_buy").default(true).notNull(),
  tradeValue: doublePrecision("trade_value"),
  status: text("status").notNull().default("active"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var transactions = pgTable("transactions", {
  id: serial("id").primaryKey(),
  transactionId: text("transaction_id").notNull().unique(),
  productId: integer("product_id").references(() => products.id).notNull(),
  buyerId: integer("buyer_id").references(() => users.id).notNull(),
  sellerId: integer("seller_id").references(() => users.id).notNull(),
  amount: doublePrecision("amount").notNull(),
  platformFee: doublePrecision("platform_fee").notNull(),
  shipping: doublePrecision("shipping").default(0),
  status: text("status").notNull(),
  type: text("type").notNull(),
  // 'purchase' or 'trade'
  tradeDetails: jsonb("trade_details"),
  timeline: jsonb("timeline").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var tradeOffers = pgTable("trade_offers", {
  id: serial("id").primaryKey(),
  buyerId: integer("buyer_id").references(() => users.id).notNull(),
  sellerId: integer("seller_id").references(() => users.id).notNull(),
  productId: integer("product_id").references(() => products.id).notNull(),
  offerValue: doublePrecision("offer_value").notNull(),
  status: text("status").default("pending").notNull(),
  // pending, accepted, rejected, completed
  buyerConfirmed: boolean("buyer_confirmed").default(false).notNull(),
  sellerConfirmed: boolean("seller_confirmed").default(false).notNull(),
  escrowAmount: doublePrecision("escrow_amount"),
  // Amount held in escrow during trade process
  relatedMessageId: integer("related_message_id"),
  offerItemName: text("offer_item_name"),
  offerItemDescription: text("offer_item_description"),
  offerItemImages: text("offer_item_images").array(),
  isDirect: boolean("is_direct").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  senderId: integer("sender_id").references(() => users.id).notNull(),
  receiverId: integer("receiver_id").references(() => users.id).notNull(),
  content: text("content").notNull(),
  images: text("images").array(),
  isRead: boolean("is_read").default(false).notNull(),
  isTrade: boolean("is_trade").default(false).notNull(),
  productId: integer("product_id").references(() => products.id),
  tradeOfferId: integer("trade_offer_id").references(() => tradeOffers.id),
  tradeDetails: text("trade_details"),
  tradeConfirmedBuyer: boolean("trade_confirmed_buyer").default(false).notNull(),
  tradeConfirmedSeller: boolean("trade_confirmed_seller").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var conversations = pgTable("conversations", {
  id: serial("id").primaryKey(),
  user1Id: integer("user1_id").references(() => users.id).notNull(),
  user2Id: integer("user2_id").references(() => users.id).notNull(),
  lastMessageId: integer("last_message_id").references(() => messages.id),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var deposits = pgTable("deposits", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  amount: doublePrecision("amount").notNull(),
  method: text("method").notNull(),
  status: text("status").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var withdrawals = pgTable("withdrawals", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  amount: doublePrecision("amount").notNull(),
  method: text("method").notNull(),
  status: text("status").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  firstName: true,
  lastName: true,
  email: true,
  avatar: true,
  location: true,
  isAdmin: true
});
var insertProductCategorySchema = createInsertSchema(productCategories);
var insertProductSchema = createInsertSchema(products).pick({
  title: true,
  description: true,
  price: true,
  images: true,
  categoryId: true,
  sellerId: true,
  location: true,
  allowTrade: true,
  allowBuy: true,
  tradeValue: true,
  status: true
});
var insertTransactionSchema = createInsertSchema(transactions).pick({
  transactionId: true,
  productId: true,
  buyerId: true,
  sellerId: true,
  amount: true,
  platformFee: true,
  shipping: true,
  status: true,
  type: true,
  tradeDetails: true,
  timeline: true
});
var insertTradeOfferSchema = createInsertSchema(tradeOffers).pick({
  buyerId: true,
  sellerId: true,
  productId: true,
  offerValue: true,
  status: true,
  buyerConfirmed: true,
  sellerConfirmed: true,
  escrowAmount: true,
  relatedMessageId: true,
  offerItemName: true,
  offerItemDescription: true,
  offerItemImages: true,
  isDirect: true
});
var insertMessageSchema = createInsertSchema(messages).pick({
  senderId: true,
  receiverId: true,
  content: true,
  images: true,
  isTrade: true,
  productId: true,
  tradeOfferId: true,
  tradeDetails: true,
  tradeConfirmedBuyer: true,
  tradeConfirmedSeller: true
});
var insertConversationSchema = createInsertSchema(conversations).pick({
  user1Id: true,
  user2Id: true,
  lastMessageId: true
});
var insertDepositSchema = createInsertSchema(deposits).pick({
  userId: true,
  amount: true,
  method: true,
  status: true
});
var insertWithdrawalSchema = createInsertSchema(withdrawals).pick({
  userId: true,
  amount: true,
  method: true,
  status: true
});

// server/trade-api.ts
import { v4 as uuidv4 } from "uuid";
async function createTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const { sellerId, productId, offerValue } = req.body;
    const buyerId = req.user.id;
    const product = await storage.getProduct(productId);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }
    const tradeOffer = {
      buyerId,
      sellerId,
      productId,
      offerValue,
      status: "pending",
      buyerConfirmed: false,
      sellerConfirmed: false
    };
    const newTradeOffer = await storage.createTradeOffer(tradeOffer);
    const content = `
**Trade Offer for: ${product.title}**

I'd like to offer my item for trade:
- **Item:** ${req.body.offerItemName || "Unnamed item"}
- **Description:** ${req.body.offerItemDescription || "No description"}
- **Trade Value:** ${(offerValue / 1e3).toFixed(3)} \u20AB


Please let me know if you're interested in this trade.
      `;
    const message = await storage.createMessage({
      senderId: buyerId,
      receiverId: sellerId,
      content,
      images: req.body.offerItemImages || [],
      isTrade: true,
      productId,
      tradeOfferId: newTradeOffer.id,
      tradeDetails: req.body.tradeDetails || null,
      tradeConfirmedBuyer: false,
      tradeConfirmedSeller: false
    });
    let conversation = await storage.getConversationByUsers(buyerId, sellerId);
    if (!conversation) {
      conversation = await storage.createConversation({
        user1Id: buyerId,
        user2Id: sellerId,
        lastMessageId: message.id
      });
    } else {
      await storage.updateConversation(conversation.id, {
        lastMessageId: message.id
      });
    }
    await storage.updateTradeOffer(newTradeOffer.id, {
      relatedMessageId: message.id
    });
    return res.status(201).json({ message, tradeOffer: newTradeOffer });
  } catch (error) {
    console.error("Error creating trade offer:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function getUserTradeOffers(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const userId = req.user.id;
    const tradeOffers2 = await storage.getUserTradeOffers(userId);
    return res.status(200).json(tradeOffers2);
  } catch (error) {
    console.error("Error getting user trade offers:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function getPendingTradeOffers(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const userId = req.user.id;
    const pendingTradeOffers = await storage.getPendingTradeOffers(userId);
    return res.status(200).json(pendingTradeOffers);
  } catch (error) {
    console.error("Error getting pending trade offers:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function getTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const tradeOfferId = parseInt(req.params.id);
    if (isNaN(tradeOfferId)) {
      return res.status(400).json({ error: "Invalid trade offer ID" });
    }
    const tradeOffer = await storage.getTradeOffer(tradeOfferId);
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    const userId = req.user.id;
    if (tradeOffer.buyerId !== userId && tradeOffer.sellerId !== userId) {
      return res.status(403).json({ error: "You don't have permission to view this trade offer" });
    }
    return res.status(200).json(tradeOffer);
  } catch (error) {
    console.error("Error getting trade offer:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function acceptTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const tradeOfferId = parseInt(req.params.id);
    if (isNaN(tradeOfferId)) {
      return res.status(400).json({ error: "Invalid trade offer ID" });
    }
    const tradeOffer = await storage.getTradeOffer(tradeOfferId);
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    const userId = req.user.id;
    if (tradeOffer.sellerId !== userId) {
      return res.status(403).json({ error: "Only the seller can accept a trade offer" });
    }
    if (tradeOffer.status !== "pending") {
      return res.status(400).json({ error: `This trade offer has already been ${tradeOffer.status}` });
    }
    const updatedTradeOffer = await storage.updateTradeOffer(tradeOfferId, {
      status: "accepted",
      sellerConfirmed: true
    });
    if (tradeOffer.relatedMessageId) {
      const message = await storage.getMessage(tradeOffer.relatedMessageId);
      if (message) {
        await storage.updateMessage(message.id, {
          tradeConfirmedSeller: true
        });
        await storage.createMessage({
          senderId: userId,
          receiverId: tradeOffer.buyerId,
          content: `Trade offer for "${req.body.productTitle || "Product"}" has been accepted. Buyer must confirm to complete the trade.`,
          isTrade: false
        });
      }
    }
    return res.status(200).json(updatedTradeOffer);
  } catch (error) {
    console.error("Error accepting trade offer:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function confirmTrade(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const tradeOfferId = parseInt(req.params.id);
    if (isNaN(tradeOfferId)) {
      return res.status(400).json({ error: "Invalid trade offer ID" });
    }
    const tradeOffer = await storage.getTradeOffer(tradeOfferId);
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    const { buyerId, sellerId } = tradeOffer;
    const userId = req.user.id;
    if (buyerId !== userId && sellerId !== userId) {
      return res.status(403).json({ error: "You don't have permission to confirm this trade" });
    }
    const isBuyer = buyerId === userId;
    const isSeller = sellerId === userId;
    if (tradeOffer.status !== "accepted") {
      return res.status(400).json({ error: "This trade offer must be accepted first" });
    }
    if (isBuyer && !tradeOffer.buyerConfirmed) {
      await storage.updateTradeOffer(tradeOfferId, {
        buyerConfirmed: true
      });
      if (tradeOffer.relatedMessageId) {
        const message = await storage.getMessage(tradeOffer.relatedMessageId);
        if (message) {
          await storage.updateMessage(message.id, {
            tradeConfirmedBuyer: true
          });
        }
      }
    } else if (isSeller && !tradeOffer.sellerConfirmed) {
      await storage.updateTradeOffer(tradeOfferId, {
        sellerConfirmed: true
      });
      if (tradeOffer.relatedMessageId) {
        const message = await storage.getMessage(tradeOffer.relatedMessageId);
        if (message) {
          await storage.updateMessage(message.id, {
            tradeConfirmedSeller: true
          });
        }
      }
    } else {
      return res.status(400).json({ error: "You have already confirmed this trade" });
    }
    const updatedTradeOffer = await storage.getTradeOffer(tradeOfferId);
    if (!updatedTradeOffer) {
      return res.status(404).json({ error: "Trade offer not found after update" });
    }
    if (updatedTradeOffer.buyerConfirmed && updatedTradeOffer.sellerConfirmed) {
      await storage.updateTradeOffer(tradeOfferId, {
        status: "completed"
      });
      const product = await storage.getProduct(tradeOffer.productId);
      if (product) {
        await storage.updateProduct(product.id, {
          status: "sold"
        });
        const feeAmount = updatedTradeOffer.offerValue * 0.1;
        const remainingAmount = updatedTradeOffer.offerValue - feeAmount;
        const transaction = await storage.createTransaction({
          buyerId: updatedTradeOffer.buyerId,
          sellerId: updatedTradeOffer.sellerId,
          productId: updatedTradeOffer.productId,
          amount: updatedTradeOffer.offerValue,
          fee: feeAmount,
          transactionId: uuidv4(),
          status: "completed",
          paymentMethod: "trade"
        });
        await storage.createMessage({
          senderId: 1,
          // Admin user ID
          receiverId: tradeOffer.buyerId,
          content: `Trade for "${product.title}" has been completed successfully! A 10% fee (${(feeAmount / 1e3).toFixed(3)} \u20AB) was applied.`,
          isTrade: false
        });
        await storage.createMessage({
          senderId: 1,
          // Admin user ID
          receiverId: tradeOffer.sellerId,
          content: `Trade for "${product.title}" has been completed successfully! A 10% fee (${(feeAmount / 1e3).toFixed(3)} \u20AB) was applied.`,
          isTrade: false
        });
        return res.status(200).json({
          tradeOffer: {
            ...updatedTradeOffer,
            status: "completed"
          },
          transaction
        });
      }
    }
    return res.status(200).json(updatedTradeOffer);
  } catch (error) {
    console.error("Error confirming trade:", error);
    return res.status(500).json({ error: error.message });
  }
}
async function rejectTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const tradeOfferId = parseInt(req.params.id);
    if (isNaN(tradeOfferId)) {
      return res.status(400).json({ error: "Invalid trade offer ID" });
    }
    const tradeOffer = await storage.getTradeOffer(tradeOfferId);
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    const userId = req.user.id;
    if (tradeOffer.buyerId !== userId && tradeOffer.sellerId !== userId) {
      return res.status(403).json({ error: "You don't have permission to reject this trade offer" });
    }
    if (tradeOffer.status === "completed") {
      return res.status(400).json({ error: "This trade has already been completed and cannot be rejected" });
    }
    if (tradeOffer.status === "rejected") {
      return res.status(400).json({ error: "This trade has already been rejected" });
    }
    const updatedTradeOffer = await storage.updateTradeOffer(tradeOfferId, {
      status: "rejected"
    });
    if (tradeOffer.relatedMessageId) {
      const message = await storage.getMessage(tradeOffer.relatedMessageId);
      if (message) {
        await storage.updateMessage(message.id, {
          tradeConfirmedBuyer: false,
          tradeConfirmedSeller: false
        });
        const isRejectedByBuyer = userId === tradeOffer.buyerId;
        const receiverId = isRejectedByBuyer ? tradeOffer.sellerId : tradeOffer.buyerId;
        await storage.createMessage({
          senderId: userId,
          receiverId,
          content: `Trade offer has been rejected by ${isRejectedByBuyer ? "buyer" : "seller"}.`,
          isTrade: false
        });
      }
    }
    return res.status(200).json(updatedTradeOffer);
  } catch (error) {
    console.error("Error rejecting trade offer:", error);
    return res.status(500).json({ error: error.message });
  }
}

// server/direct-trade-api.ts
import { v4 as uuidv42 } from "uuid";
async function createDirectTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "You must be logged in" });
    }
    const user = req.user;
    const {
      productId,
      sellerId,
      offerValue,
      offerItemName,
      offerItemDescription,
      offerItemImage,
      offerItemImages,
      // Accept offerItemImages directly
      status
    } = req.body;
    if (!productId || !sellerId) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (user.id === sellerId) {
      return res.status(400).json({ error: "You cannot trade with yourself" });
    }
    const product = await storage.getProduct(productId);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }
    if (offerItemImage) {
      console.log("Creating trade offer with image:", "Image exists (length: " + offerItemImage.length + ")");
    } else if (offerItemImages) {
      console.log("Creating trade offer with images array:", "Array exists with length: " + offerItemImages.length);
    } else {
      console.log("Creating trade offer with no images");
    }
    const tradeOffer = await storage.createTradeOffer({
      productId,
      sellerId,
      buyerId: user.id,
      status: status || "pending",
      // pending, accepted, rejected, completed
      offerValue,
      offerItemName,
      offerItemDescription,
      offerItemImages: offerItemImages || (offerItemImage ? [offerItemImage] : []),
      // Use array if provided
      isDirect: true,
      createdAt: /* @__PURE__ */ new Date(),
      updatedAt: /* @__PURE__ */ new Date()
    });
    res.status(201).json(tradeOffer);
  } catch (error) {
    console.error("Error creating direct trade offer:", error);
    res.status(500).json({ error: error.message || "Failed to create trade offer" });
  }
}
async function getDirectTradeOffers(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "You must be logged in" });
    }
    const user = req.user;
    const tradeOffers2 = await storage.getUserTradeOffers(user.id);
    res.json(tradeOffers2);
  } catch (error) {
    console.error("Error getting trade offers:", error);
    res.status(500).json({ error: error.message || "Failed to get trade offers" });
  }
}
async function getDirectTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "You must be logged in" });
    }
    const { id } = req.params;
    const tradeOffer = await storage.getTradeOffer(Number(id));
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    res.json(tradeOffer);
  } catch (error) {
    console.error("Error getting trade offer:", error);
    res.status(500).json({ error: error.message || "Failed to get trade offer" });
  }
}
async function acceptDirectTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "You must be logged in" });
    }
    const user = req.user;
    const { id } = req.params;
    const tradeOffer = await storage.getTradeOffer(Number(id));
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    if (tradeOffer.sellerId !== user.id) {
      return res.status(403).json({ error: "Only the seller can accept a trade offer" });
    }
    if (tradeOffer.status !== "pending") {
      return res.status(400).json({ error: `Trade offer is already ${tradeOffer.status}` });
    }
    const product = await storage.getProduct(tradeOffer.productId);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }
    const escrowAmount = Math.max(
      product.tradeValue || 0,
      tradeOffer.offerValue || 0
    );
    if (user.balance < escrowAmount) {
      return res.status(400).json({
        error: `You need at least ${escrowAmount.toLocaleString("vi-VN")} \u20AB in your account to accept this trade. This amount will be held in escrow until the trade is completed.`
      });
    }
    const buyer = await storage.getUser(tradeOffer.buyerId);
    if (!buyer) {
      return res.status(404).json({ error: "Buyer not found" });
    }
    if (buyer.balance < escrowAmount) {
      return res.status(400).json({
        error: `The buyer doesn't have enough funds (${escrowAmount.toLocaleString("vi-VN")} \u20AB) to complete this trade.`
      });
    }
    await storage.updateUser(user.id, {
      balance: user.balance - escrowAmount
    });
    await storage.updateUser(buyer.id, {
      balance: buyer.balance - escrowAmount
    });
    const updatedOffer = await storage.updateTradeOffer(Number(id), {
      status: "accepted",
      escrowAmount,
      updatedAt: /* @__PURE__ */ new Date()
    });
    res.json(updatedOffer);
  } catch (error) {
    console.error("Error accepting trade offer:", error);
    res.status(500).json({ error: error.message || "Failed to accept trade offer" });
  }
}
async function confirmDirectTrade(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "You must be logged in" });
    }
    const user = req.user;
    const { id } = req.params;
    const tradeOffer = await storage.getTradeOffer(Number(id));
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    if (tradeOffer.buyerId !== user.id) {
      return res.status(403).json({ error: "Only the buyer can confirm a trade" });
    }
    if (tradeOffer.status !== "accepted") {
      return res.status(400).json({ error: `Trade offer must be accepted first` });
    }
    const product = await storage.getProduct(tradeOffer.productId);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }
    const productValue = product.tradeValue || 0;
    const offerValue = tradeOffer.offerValue || 0;
    const tradeValue = Math.max(productValue, offerValue);
    const platformFee = Math.round(tradeValue * 0.1);
    const escrowAmount = tradeOffer.escrowAmount || 0;
    const seller = await storage.getUser(tradeOffer.sellerId);
    if (seller) {
      const amountToReturn = escrowAmount - platformFee;
      await storage.updateUser(seller.id, {
        balance: seller.balance + amountToReturn
      });
    }
    const buyer = await storage.getUser(tradeOffer.buyerId);
    if (buyer && buyer.id !== user.id) {
      await storage.updateUser(buyer.id, {
        balance: buyer.balance + escrowAmount - platformFee
      });
    } else {
      await storage.updateUser(user.id, {
        balance: user.balance + escrowAmount - platformFee
      });
    }
    const transaction = await storage.createTransaction({
      productId: tradeOffer.productId,
      sellerId: tradeOffer.sellerId,
      buyerId: tradeOffer.buyerId,
      type: "trade",
      status: "completed",
      amount: tradeValue,
      platformFee,
      transactionId: uuidv42(),
      timeline: [
        {
          status: "created",
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          note: "Trade initiated"
        },
        {
          status: "completed",
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          note: "Trade completed successfully, escrow released minus platform fee"
        }
      ],
      tradeDetails: {
        tradeOfferId: tradeOffer.id,
        offerItemName: tradeOffer.offerItemName,
        offerItemDescription: tradeOffer.offerItemDescription,
        offerItemImages: tradeOffer.offerItemImages,
        // Use the images array from trade offer
        offerValue: tradeOffer.offerValue,
        escrowAmount,
        escrowReleased: escrowAmount - platformFee
      }
    });
    const updatedOffer = await storage.updateTradeOffer(Number(id), {
      status: "completed"
    });
    await storage.updateProduct(product.id, {
      status: "sold"
    });
    res.json({
      tradeOffer: updatedOffer,
      transaction
    });
  } catch (error) {
    console.error("Error confirming trade:", error);
    res.status(500).json({ error: error.message || "Failed to confirm trade" });
  }
}
async function rejectDirectTradeOffer(req, res) {
  try {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "You must be logged in" });
    }
    const user = req.user;
    const { id } = req.params;
    const tradeOffer = await storage.getTradeOffer(Number(id));
    if (!tradeOffer) {
      return res.status(404).json({ error: "Trade offer not found" });
    }
    if (tradeOffer.sellerId !== user.id && tradeOffer.buyerId !== user.id) {
      return res.status(403).json({ error: "Only the buyer or seller can reject a trade offer" });
    }
    if (tradeOffer.status !== "pending" && tradeOffer.status !== "accepted") {
      return res.status(400).json({ error: `Trade offer cannot be rejected when it's ${tradeOffer.status}` });
    }
    if (tradeOffer.status === "accepted" && tradeOffer.escrowAmount) {
      const seller = await storage.getUser(tradeOffer.sellerId);
      if (seller) {
        await storage.updateUser(seller.id, {
          balance: seller.balance + tradeOffer.escrowAmount
        });
      }
      const buyer = await storage.getUser(tradeOffer.buyerId);
      if (buyer) {
        await storage.updateUser(buyer.id, {
          balance: buyer.balance + tradeOffer.escrowAmount
        });
      }
    }
    const updatedOffer = await storage.updateTradeOffer(Number(id), {
      status: "rejected"
    });
    res.json(updatedOffer);
  } catch (error) {
    console.error("Error rejecting trade offer:", error);
    res.status(500).json({ error: error.message || "Failed to reject trade offer" });
  }
}

// server/routes.ts
import { randomBytes as randomBytes2 } from "crypto";
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).send("Unauthorized");
}
function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user?.isAdmin) {
    return next();
  }
  res.status(403).send("Forbidden");
}
async function registerRoutes(app2) {
  setupAuth(app2);
  app2.get("/api/categories", async (req, res) => {
    try {
      const categories = await storage.getCategories();
      res.json(categories);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch categories" });
    }
  });
  app2.get("/api/categories/:id", async (req, res) => {
    try {
      const categoryId = parseInt(req.params.id);
      const category = await storage.getCategory(categoryId);
      if (!category) {
        return res.status(404).json({ error: "Category not found" });
      }
      res.json(category);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch category" });
    }
  });
  app2.get("/api/products", async (req, res) => {
    try {
      const limit = req.query.limit ? parseInt(req.query.limit) : 10;
      const products2 = await storage.getRecentProducts(limit);
      const availableProducts = products2.filter((product) => product.status !== "sold");
      res.json(availableProducts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch products" });
    }
  });
  app2.get("/api/products/category/:id", async (req, res) => {
    try {
      const categoryId = parseInt(req.params.id);
      const products2 = await storage.getProductsByCategory(categoryId);
      const availableProducts = products2.filter((product) => product.status !== "sold");
      console.log(`Returning ${availableProducts.length} products for category ${categoryId}`);
      res.json(availableProducts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch products by category" });
    }
  });
  app2.get("/api/products/:id", async (req, res) => {
    try {
      const productId = parseInt(req.params.id);
      const product = await storage.getProduct(productId);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      res.json(product);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch product" });
    }
  });
  app2.post("/api/products", ensureAuthenticated, async (req, res) => {
    try {
      const productData = insertProductSchema.parse({
        ...req.body,
        sellerId: req.user.id
      });
      const product = await storage.createProduct(productData);
      res.status(201).json(product);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to create product" });
    }
  });
  app2.put("/api/products/:id", ensureAuthenticated, async (req, res) => {
    try {
      const productId = parseInt(req.params.id);
      const product = await storage.getProduct(productId);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      if (product.sellerId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: "Unauthorized" });
      }
      const updates = req.body;
      const updatedProduct = await storage.updateProduct(productId, updates);
      res.json(updatedProduct);
    } catch (error) {
      res.status(500).json({ error: "Failed to update product" });
    }
  });
  app2.get("/api/transactions", ensureAuthenticated, async (req, res) => {
    try {
      const transactions2 = await storage.getUserTransactions(req.user.id);
      res.json(transactions2);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch transactions" });
    }
  });
  app2.get("/api/transactions/:id", ensureAuthenticated, async (req, res) => {
    try {
      const transactionId = parseInt(req.params.id);
      const transaction = await storage.getTransaction(transactionId);
      if (!transaction) {
        return res.status(404).json({ error: "Transaction not found" });
      }
      if (transaction.buyerId !== req.user.id && transaction.sellerId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: "Unauthorized" });
      }
      res.json(transaction);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch transaction" });
    }
  });
  app2.post("/api/transactions", ensureAuthenticated, async (req, res) => {
    try {
      const buyerId = req.user.id;
      const product = await storage.getProduct(req.body.productId);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      if (product.sellerId === buyerId) {
        return res.status(400).json({ error: "Cannot buy/trade your own product" });
      }
      const feePercentage = req.body.type === "trade" ? 0.1 : 0.15;
      const platformFee = req.body.amount * feePercentage;
      const transactionId = `TRX${Date.now().toString().slice(-5)}${randomBytes2(2).toString("hex").toUpperCase()}`;
      const timeline = [{
        timestamp: /* @__PURE__ */ new Date(),
        status: "initiated",
        description: req.body.type === "trade" ? "Trade initiated" : "Payment initiated"
      }];
      const transactionData = insertTransactionSchema.parse({
        ...req.body,
        transactionId,
        buyerId,
        sellerId: product.sellerId,
        platformFee,
        status: "pending",
        timeline
      });
      const transaction = await storage.createTransaction(transactionData);
      const buyer = await storage.getUser(buyerId);
      if (buyer) {
        if (buyer.balance < req.body.amount) {
          return res.status(400).json({ error: "Insufficient balance" });
        }
        await storage.updateUser(buyerId, {
          balance: buyer.balance - req.body.amount,
          escrowBalance: buyer.escrowBalance + req.body.amount
        });
      }
      res.status(201).json(transaction);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to create transaction" });
    }
  });
  app2.put("/api/transactions/:id", ensureAuthenticated, async (req, res) => {
    try {
      const transactionId = parseInt(req.params.id);
      const transaction = await storage.getTransaction(transactionId);
      if (!transaction) {
        return res.status(404).json({ error: "Transaction not found" });
      }
      if (transaction.buyerId !== req.user.id && transaction.sellerId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: "Unauthorized" });
      }
      if (req.body.status && req.body.status !== transaction.status) {
        const newStatus = req.body.status;
        const timelineEntry = {
          timestamp: /* @__PURE__ */ new Date(),
          status: newStatus,
          description: `Transaction ${newStatus}`,
          updatedBy: req.user.id
        };
        const timeline = Array.isArray(transaction.timeline) ? [...transaction.timeline, timelineEntry] : [timelineEntry];
        if (newStatus === "completed") {
          const buyer = await storage.getUser(transaction.buyerId);
          const seller = await storage.getUser(transaction.sellerId);
          if (buyer && seller) {
            if (transaction.type === "trade") {
              const refundAmount = transaction.amount * 0.9;
              await storage.updateUser(buyer.id, {
                escrowBalance: buyer.escrowBalance - transaction.amount,
                balance: buyer.balance + refundAmount
              });
              const sellerAmount = transaction.amount - transaction.platformFee;
              await storage.updateUser(seller.id, {
                balance: seller.balance + sellerAmount
              });
            } else {
              await storage.updateUser(buyer.id, {
                escrowBalance: buyer.escrowBalance - transaction.amount
              });
              const sellerAmount = transaction.amount - transaction.platformFee;
              await storage.updateUser(seller.id, {
                balance: seller.balance + sellerAmount
              });
            }
            await storage.updateProduct(transaction.productId, {
              status: "sold"
            });
          }
        }
        if (newStatus === "cancelled" || newStatus === "refunded") {
          const buyer = await storage.getUser(transaction.buyerId);
          if (buyer) {
            await storage.updateUser(buyer.id, {
              escrowBalance: buyer.escrowBalance - transaction.amount,
              balance: buyer.balance + transaction.amount
            });
          }
        }
        req.body.timeline = timeline;
      }
      const updatedTransaction = await storage.updateTransaction(transactionId, req.body);
      res.json(updatedTransaction);
    } catch (error) {
      res.status(500).json({ error: "Failed to update transaction" });
    }
  });
  app2.get("/api/debug/trade-messages", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const allMessages = [];
      const conversations2 = await storage.getUserConversations(userId);
      for (const conversation of conversations2) {
        const messages2 = await storage.getMessages(conversation.id);
        allMessages.push(...messages2);
      }
      const tradeMessages = allMessages.filter((msg) => msg.isTrade === true);
      res.json({
        conversations: conversations2.length,
        allMessages: allMessages.length,
        tradeMessages
      });
    } catch (error) {
      console.error("Error debugging trade messages:", error);
      res.status(500).json({ error: "Error debugging trade messages" });
    }
  });
  app2.get("/api/conversations", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      console.log(`Fetching conversations for user ${userId}`);
      const conversations2 = await storage.getUserConversations(userId);
      console.log(`Found ${conversations2.length} conversations for user ${userId}`);
      const enhancedConversations = await Promise.all(conversations2.map(async (conversation) => {
        try {
          const otherUserId = conversation.user1Id === userId ? conversation.user2Id : conversation.user1Id;
          const otherUser = await storage.getUser(otherUserId);
          if (!otherUser) {
            console.error(`Other user ${otherUserId} not found for conversation ${conversation.id}`);
            return null;
          }
          const messages2 = await storage.getMessages(conversation.id);
          console.log(`Found ${messages2.length} messages for conversation ${conversation.id}`);
          let lastMessage = null;
          if (conversation.lastMessageId) {
            lastMessage = messages2.find((msg) => msg.id === conversation.lastMessageId) || null;
            if (!lastMessage && messages2.length > 0) {
              lastMessage = messages2[messages2.length - 1];
              await storage.updateConversation(conversation.id, {
                lastMessageId: lastMessage.id
              });
            }
          } else if (messages2.length > 0) {
            lastMessage = messages2[messages2.length - 1];
            await storage.updateConversation(conversation.id, {
              lastMessageId: lastMessage.id
            });
          }
          const unreadCount = messages2.filter(
            (msg) => msg.receiverId === userId && !msg.isRead
          ).length;
          return {
            ...conversation,
            otherUser,
            lastMessage,
            messages: messages2,
            // Include all messages
            unreadCount
          };
        } catch (err) {
          console.error(`Error processing conversation ${conversation.id}:`, err);
          return null;
        }
      }));
      const validConversations = enhancedConversations.filter(Boolean);
      console.log(`Returning ${validConversations.length} valid conversations for user ${userId}`);
      res.json(validConversations);
    } catch (error) {
      console.error("Error fetching conversations:", error);
      res.status(500).json({ error: "Failed to fetch conversations" });
    }
  });
  app2.get("/api/conversations/:id", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const conversationId = parseInt(req.params.id);
      if (isNaN(conversationId)) {
        return res.status(400).json({ error: "Invalid conversation ID" });
      }
      console.log(`Fetching conversation ${conversationId} for user ${userId}`);
      const conversation = await storage.getConversation(conversationId);
      if (!conversation) {
        console.log(`Conversation ${conversationId} not found`);
        return res.status(404).json({ error: "Conversation not found" });
      }
      if (conversation.user1Id !== userId && conversation.user2Id !== userId) {
        console.log(`User ${userId} is not authorized to view conversation ${conversationId}`);
        return res.status(403).json({ error: "Unauthorized" });
      }
      const messages2 = await storage.getMessages(conversationId);
      console.log(`Found ${messages2.length} messages for conversation ${conversationId}`);
      const otherUserId = conversation.user1Id === userId ? conversation.user2Id : conversation.user1Id;
      const otherUser = await storage.getUser(otherUserId);
      if (!otherUser) {
        console.error(`Other user ${otherUserId} not found for conversation ${conversationId}`);
        return res.status(500).json({ error: "Failed to load conversation partner details" });
      }
      let markedCount = 0;
      for (const message of messages2) {
        if (message.receiverId === userId && !message.isRead) {
          await storage.markMessageAsRead(message.id);
          markedCount++;
        }
      }
      if (markedCount > 0) {
        console.log(`Marked ${markedCount} messages as read for user ${userId}`);
      }
      console.log(`Conversation structure: user1=${conversation.user1Id}, user2=${conversation.user2Id}`);
      console.log(`Messages check: Total=${messages2.length}, Sample=${messages2.length > 0 ? JSON.stringify(messages2[0]) : "None"}`);
      console.log(`Other user details: ${JSON.stringify(otherUser)}`);
      const validatedMessages = messages2.map((message) => {
        if (typeof message.isTrade !== "boolean") {
          return { ...message, isTrade: message.isTrade === true };
        }
        return message;
      });
      console.log(`Successfully fetched conversation ${conversationId} with ${validatedMessages.length} messages`);
      res.json({
        conversation,
        messages: validatedMessages,
        otherUser
      });
    } catch (error) {
      console.error("Error fetching conversation details:", error);
      res.status(500).json({ error: "Failed to fetch conversation" });
    }
  });
  app2.get("/api/products/trade-messages", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      console.log(`Fetching products for trade messages for user ${userId}`);
      const conversations2 = await storage.getUserConversations(userId);
      const conversationIds = conversations2.map((c) => c.id);
      const productIds = /* @__PURE__ */ new Set();
      for (const conversationId of conversationIds) {
        const messages2 = await storage.getMessages(conversationId);
        for (const message of messages2) {
          if (message.isTrade && message.productId) {
            productIds.add(message.productId);
          }
        }
      }
      console.log(`Found ${productIds.size} unique product IDs in trade messages`);
      const products2 = [];
      const productPromises = Array.from(productIds).map(
        (productId) => storage.getProduct(productId)
      );
      const fetchedProducts = await Promise.all(productPromises);
      for (const product of fetchedProducts) {
        if (product) {
          products2.push(product);
        }
      }
      if (products2.length === 0) {
        console.log("No products found in trade messages, fetching recent products as fallback");
        const recentProducts = await storage.getRecentProducts(10);
        products2.push(...recentProducts);
      }
      const productMap = products2.reduce((map, product) => {
        map[product.id] = product;
        return map;
      }, {});
      console.log(`Returning ${Object.keys(productMap).length} products for trade messages`);
      res.json(productMap);
    } catch (error) {
      console.error("Error fetching products for trade messages:", error);
      res.status(500).json({ error: "Failed to fetch products" });
    }
  });
  app2.all("/api/trade/simple-accept", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const messageId = req.method === "GET" ? parseInt(req.query.messageId) : req.body.messageId;
      console.log(`=== DIRECT TRADE ACCEPTANCE ===`);
      console.log(`User ${userId} accepting trade for message ${messageId} via ${req.method}`);
      const message = await storage.getMessage(messageId);
      if (!message) {
        return res.status(404).json({ error: "Message not found" });
      }
      if (!message.isTrade || !message.productId) {
        return res.status(400).json({ error: "Not a valid trade message" });
      }
      const product = await storage.getProduct(message.productId);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      console.log(`Found product ${product.id}: ${product.title}`);
      const isSeller = userId === product.sellerId;
      console.log(`User is ${isSeller ? "SELLER" : "BUYER"}`);
      if (isSeller) {
        await storage.updateProduct(product.id, { status: "sold" });
        console.log(`Marked product ${product.id} as sold`);
        const tradeValue = product.tradeValue || 0;
        const fee = Math.round(tradeValue * 0.1);
        const transaction = await storage.createTransaction({
          transactionId: `TRADE-${Date.now()}`,
          productId: product.id,
          buyerId: message.senderId === product.sellerId ? message.receiverId : message.senderId,
          sellerId: product.sellerId,
          amount: tradeValue,
          platformFee: fee,
          shipping: 0,
          status: "completed",
          type: "trade",
          tradeDetails: {
            messageId,
            productName: product.title,
            fee
          },
          timeline: [
            {
              status: "completed",
              timestamp: /* @__PURE__ */ new Date(),
              note: `Trade completed by seller. Fee: ${fee.toLocaleString("vi-VN")} \u20AB`
            }
          ]
        });
        console.log(`Created transaction ${transaction.id}`);
        return res.json({
          success: true,
          message: "Trade completed successfully. Product is now sold.",
          tradeDone: true
        });
      } else {
        const updatedMessage = await storage.updateMessage(messageId, {
          tradeConfirmedBuyer: true
        });
        console.log(`Updated message ${messageId} with buyer confirmation`);
        return res.json({
          success: true,
          message: "Your trade acceptance has been recorded. Waiting for seller to accept.",
          tradeDone: false
        });
      }
    } catch (error) {
      console.error("Error accepting trade:", error);
      res.status(500).json({ error: "Failed to process trade acceptance" });
    }
  });
  app2.post("/api/messages", ensureAuthenticated, async (req, res) => {
    try {
      const senderId = req.user.id;
      const { receiverId, content, images, isTrade, productId } = req.body;
      if (!receiverId) {
        return res.status(400).json({ error: "Receiver ID is required" });
      }
      if (!content || content.trim() === "") {
        return res.status(400).json({ error: "Message content cannot be empty" });
      }
      let conversation = await storage.getConversationByUsers(senderId, receiverId);
      if (!conversation) {
        const sender = await storage.getUser(senderId);
        const receiver = await storage.getUser(receiverId);
        if (!sender || !receiver) {
          return res.status(404).json({ error: "One or both users not found" });
        }
        conversation = await storage.createConversation({
          user1Id: senderId,
          user2Id: receiverId,
          lastMessageId: null
        });
        console.log(`Created new conversation between users ${senderId} and ${receiverId} with ID: ${conversation.id}`);
      } else {
        console.log(`Found existing conversation with ID: ${conversation.id}`);
      }
      const messageData = {
        senderId,
        receiverId,
        content,
        images: images || null,
        isTrade: isTrade || false,
        productId: productId || null,
        tradeConfirmedBuyer: false,
        tradeConfirmedSeller: false
      };
      const message = await storage.createMessage(messageData);
      console.log(`Created new message with ID: ${message.id} in conversation ${conversation.id}`);
      await storage.updateConversation(conversation.id, {
        lastMessageId: message.id,
        updatedAt: /* @__PURE__ */ new Date()
      });
      res.status(201).json(message);
    } catch (error) {
      console.error("Error sending message:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to send message" });
    }
  });
  app2.post("/api/deposits", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const depositData = insertDepositSchema.parse({
        ...req.body,
        userId,
        status: "pending"
        // Changed to pending - requires admin approval
      });
      const deposit = await storage.createDeposit(depositData);
      res.status(201).json(deposit);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to process deposit" });
    }
  });
  app2.post("/api/withdrawals", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const { amount, method } = req.body;
      const user = await storage.getUser(userId);
      if (!user || user.balance < amount) {
        return res.status(400).json({ error: "Insufficient balance" });
      }
      const withdrawalData = insertWithdrawalSchema.parse({
        userId,
        amount,
        method,
        status: "pending"
      });
      const withdrawal = await storage.createWithdrawal(withdrawalData);
      await storage.updateUser(userId, {
        balance: user.balance - amount
      });
      res.status(201).json(withdrawal);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to process withdrawal" });
    }
  });
  app2.get("/api/admin/users", ensureAdmin, async (req, res) => {
    try {
      const users2 = await Promise.all(
        Array.from({ length: 100 }, (_, i) => i + 1).map((id) => storage.getUser(id))
      );
      res.json(users2.filter(Boolean));
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });
  app2.post("/api/admin/users/:id/balance", ensureAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const { amount } = req.body;
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const updatedUser = await storage.updateUser(userId, {
        balance: user.balance + amount
      });
      res.json(updatedUser);
    } catch (error) {
      res.status(500).json({ error: "Failed to update user balance" });
    }
  });
  app2.get("/api/admin/deposits", ensureAdmin, async (req, res) => {
    try {
      const deposits2 = [];
      for (let i = 1; i <= 100; i++) {
        const deposit = await storage.getDeposit(i);
        if (deposit) {
          const user = await storage.getUser(deposit.userId);
          deposits2.push({
            ...deposit,
            username: user?.username || "Unknown"
          });
        }
      }
      deposits2.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      res.json(deposits2);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch deposits" });
    }
  });
  app2.post("/api/admin/deposits/:id/approve", ensureAdmin, async (req, res) => {
    try {
      const depositId = parseInt(req.params.id);
      const deposit = await storage.getDeposit(depositId);
      if (!deposit) {
        return res.status(404).json({ error: "Deposit not found" });
      }
      if (deposit.status !== "pending") {
        return res.status(400).json({ error: "Deposit is not in pending status" });
      }
      const updatedDeposit = await storage.updateDeposit(depositId, {
        status: "completed"
      });
      const user = await storage.getUser(deposit.userId);
      if (user) {
        await storage.updateUser(deposit.userId, {
          balance: user.balance + deposit.amount
        });
      }
      res.json(updatedDeposit);
    } catch (error) {
      res.status(500).json({ error: "Failed to approve deposit" });
    }
  });
  app2.post("/api/admin/deposits/:id/reject", ensureAdmin, async (req, res) => {
    try {
      const depositId = parseInt(req.params.id);
      const deposit = await storage.getDeposit(depositId);
      if (!deposit) {
        return res.status(404).json({ error: "Deposit not found" });
      }
      if (deposit.status !== "pending") {
        return res.status(400).json({ error: "Deposit is not in pending status" });
      }
      const updatedDeposit = await storage.updateDeposit(depositId, {
        status: "rejected"
      });
      res.json(updatedDeposit);
    } catch (error) {
      res.status(500).json({ error: "Failed to reject deposit" });
    }
  });
  app2.delete("/api/admin/products/:id", ensureAdmin, async (req, res) => {
    try {
      const productId = parseInt(req.params.id);
      const product = await storage.getProduct(productId);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      await storage.updateProduct(productId, { status: "deleted" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete product" });
    }
  });
  app2.get("/api/admin/transactions", ensureAdmin, async (req, res) => {
    try {
      const transactions2 = [];
      for (let i = 1; i <= 100; i++) {
        const transaction = await storage.getTransaction(i);
        if (transaction) {
          transactions2.push(transaction);
        }
      }
      transactions2.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      res.json(transactions2);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch transactions" });
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const existingUsername = await storage.getUserByUsername(req.body.username);
      if (existingUsername) {
        return res.status(400).send("Username already exists");
      }
      const existingEmail = await storage.getUserByEmail(req.body.email);
      if (existingEmail) {
        return res.status(400).send("Email already registered");
      }
      next();
    } catch (error) {
      res.status(500).json({ error: "Failed to register user" });
    }
  });
  app2.post("/api/trade-offers", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const {
        productId,
        sellerId,
        offerMessage,
        offerItemName,
        offerItemDescription,
        offerItemValue,
        offerItemImages
      } = req.body;
      if (!productId || !sellerId || !offerMessage || !offerItemName || !offerItemDescription || !offerItemValue) {
        return res.status(400).json({ error: "Missing required fields for trade offer" });
      }
      const product = await storage.getProduct(productId);
      if (!product) {
        return res.status(404).json({ error: "Product not found" });
      }
      if (!product.allowTrade) {
        return res.status(400).json({ error: "This product doesn't allow trades" });
      }
      if (userId === sellerId) {
        return res.status(400).json({ error: "You cannot trade with yourself" });
      }
      const tradeDetails = {
        offerItemName,
        offerItemDescription,
        offerItemValue,
        offerItemImages: offerItemImages || [],
        productId,
        productTitle: product.title,
        productImage: product.images[0],
        status: "pending"
      };
      let conversation = await storage.getConversationByUsers(userId, sellerId);
      if (!conversation) {
        conversation = await storage.createConversation({
          user1Id: userId,
          user2Id: sellerId,
          lastMessageId: null
        });
      }
      const message = await storage.createMessage({
        senderId: userId,
        receiverId: sellerId,
        content: offerMessage,
        isTrade: true,
        productId,
        tradeDetails: JSON.stringify(tradeDetails),
        tradeConfirmedBuyer: false,
        tradeConfirmedSeller: false,
        images: offerItemImages || null
      });
      await storage.updateConversation(conversation.id, {
        lastMessageId: message.id,
        updatedAt: /* @__PURE__ */ new Date()
      });
      res.status(201).json({
        message,
        conversation
      });
    } catch (error) {
      console.error("Error creating trade offer:", error);
      res.status(500).json({ error: "Failed to create trade offer" });
    }
  });
  app2.post("/api/trade-offers/:messageId/accept", ensureAuthenticated, async (req, res) => {
    try {
      const userId = req.user.id;
      const messageId = parseInt(req.params.messageId);
      const message = await storage.getMessage(messageId);
      if (!message) {
        return res.status(404).json({ error: "Trade offer not found" });
      }
      if (!message.isTrade) {
        return res.status(400).json({ error: "This message is not a trade offer" });
      }
      const isBuyer = message.receiverId === userId;
      const isSeller = message.senderId === userId;
      if (!isBuyer && !isSeller) {
        return res.status(403).json({ error: "You are not authorized to accept this trade" });
      }
      const updates = {};
      if (isBuyer) {
        updates.tradeConfirmedBuyer = true;
      }
      if (isSeller) {
        updates.tradeConfirmedSeller = true;
      }
      const updatedMessage = await storage.updateMessage(messageId, updates);
      if (updatedMessage.tradeConfirmedBuyer && updatedMessage.tradeConfirmedSeller) {
        let tradeDetails;
        try {
          tradeDetails = JSON.parse(updatedMessage.tradeDetails || "{}");
        } catch (e) {
          console.error("Failed to parse trade details:", e);
          tradeDetails = {};
        }
        const product = await storage.getProduct(updatedMessage.productId);
        if (!product) {
          return res.status(404).json({ error: "Product not found" });
        }
        const transaction = await storage.createTransaction({
          transactionId: `TRADE-${Date.now()}`,
          productId: updatedMessage.productId,
          buyerId: updatedMessage.senderId,
          // The person who initiated the trade is the buyer
          sellerId: updatedMessage.receiverId,
          // The person who received the trade offer is the seller
          amount: 0,
          // Trade has no monetary value in the system
          platformFee: 0,
          // No fee for trades
          shipping: null,
          status: "processing",
          type: "trade",
          tradeDetails: updatedMessage.tradeDetails,
          timeline: [
            {
              status: "created",
              timestamp: /* @__PURE__ */ new Date(),
              note: "Trade confirmed by both parties"
            }
          ]
        });
        res.status(200).json({
          message: updatedMessage,
          transaction,
          status: "completed"
        });
      } else {
        res.status(200).json({
          message: updatedMessage,
          status: "pending"
        });
      }
    } catch (error) {
      console.error("Error accepting trade offer:", error);
      res.status(500).json({ error: "Failed to accept trade offer" });
    }
  });
  app2.post("/api/trade-offers", ensureAuthenticated, createTradeOffer);
  app2.get("/api/trade-offers", ensureAuthenticated, getUserTradeOffers);
  app2.get("/api/trade-offers/pending", ensureAuthenticated, getPendingTradeOffers);
  app2.get("/api/trade-offers/:id", ensureAuthenticated, getTradeOffer);
  app2.post("/api/trade-offers/:id/accept", ensureAuthenticated, acceptTradeOffer);
  app2.post("/api/trade-offers/:id/confirm", ensureAuthenticated, confirmTrade);
  app2.post("/api/trade-offers/:id/reject", ensureAuthenticated, rejectTradeOffer);
  app2.post("/api/direct-trades", ensureAuthenticated, createDirectTradeOffer);
  app2.get("/api/direct-trades", ensureAuthenticated, getDirectTradeOffers);
  app2.get("/api/direct-trades/:id", ensureAuthenticated, getDirectTradeOffer);
  app2.post("/api/direct-trades/:id/accept", ensureAuthenticated, acceptDirectTradeOffer);
  app2.post("/api/direct-trades/:id/confirm", ensureAuthenticated, confirmDirectTrade);
  app2.post("/api/direct-trades/:id/reject", ensureAuthenticated, rejectDirectTradeOffer);
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    themePlugin(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json({ limit: "10mb" }));
app.use(express2.urlencoded({ extended: false, limit: "10mb" }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
