import { randomUUID } from "node:crypto";

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: Date;
}

/**
 * In-memory user store. Swap for a database-backed implementation
 * with the same interface in a real deployment.
 */
export class UserStore {
  private byId = new Map<string, User>();
  private byEmail = new Map<string, User>();

  create(email: string, passwordHash: string): User {
    const normalized = email.toLowerCase();
    if (this.byEmail.has(normalized)) {
      throw new Error("EMAIL_TAKEN");
    }
    const user: User = { id: randomUUID(), email: normalized, passwordHash, createdAt: new Date() };
    this.byId.set(user.id, user);
    this.byEmail.set(normalized, user);
    return user;
  }

  findByEmail(email: string): User | undefined {
    return this.byEmail.get(email.toLowerCase());
  }

  findById(id: string): User | undefined {
    return this.byId.get(id);
  }

  /** Removes the user. Returns false if no such user existed. */
  delete(id: string): boolean {
    const user = this.byId.get(id);
    if (!user) return false;
    this.byId.delete(id);
    this.byEmail.delete(user.email);
    return true;
  }
}
