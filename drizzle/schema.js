import { relations } from "drizzle-orm";
import {
  serial,
  timestamp,
  text,
  int,
  boolean,
  mysqlTable,
  varchar,
} from "drizzle-orm/mysql-core";

export const shortLink = mysqlTable("short_link", {
  id: int().autoincrement().primaryKey(),
  url: varchar({ length: 255 }).notNull(),
  shortCode: varchar("short_code", { length: 20 }).notNull().unique(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
  userId: int("user_id")
    .notNull()
    .references(() => users.id),
});

export const sessionsTable = mysqlTable("sessions", {
  id: int().autoincrement().primaryKey(),
  userId: int("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  valid: boolean().default(true).notNull(),
  userAgent: text("user_agent"),
  ip: varchar({ length: 255 }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const users = mysqlTable("users", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  password: varchar("password", { length: 255 }).notNull(),
  isEmailValid: boolean("is_email_valid").default(false).notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const usersRelation = relations(users, ({ many }) => ({
  shortLink: many(shortLink),
  session: many(sessionsTable),
}));

export const shortLinksRelation = relations(shortLink, ({ one }) => ({
  user: one(users, {
    fields: [shortLink.userId],
    references: [users.id],
  }),
}));

export const sessionsRelation = relations(sessionsTable, ({ one }) => ({
  user: one(users, {
    fields: [sessionsTable.userId], // foregin key
    references: [users.id],
  }),
}));
