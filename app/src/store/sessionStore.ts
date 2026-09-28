import { create } from "zustand";
import type { Session } from "../api/sessions";
import {
  createSession as apiCreateSession,
  getSession as apiGetSession,
  deleteSession as apiDeleteSession,
  listSessions as apiListSessions,
} from "../api/sessions";
import { setStoredSessionId, clearStoredSessionId, getStoredSessionId } from "../api/client";

// ─── State shape ──────────────────────────────────────────────────────────────

interface SessionState {
  currentSession: Session | null;
  sessions: Session[];
  isConnecting: boolean;
  error: string | null;
}

interface SessionActions {
  createSession: (target: string) => Promise<Session>;
  loadSession: (id: string) => Promise<void>;
  clearSession: () => void;
  loadSessions: () => Promise<void>;
  deleteSession: (id: string) => Promise<void>;
  hydrate: () => Promise<void>;
}

type SessionStore = SessionState & SessionActions;

// ─── Store ────────────────────────────────────────────────────────────────────

export const useSessionStore = create<SessionStore>((set, get) => ({
  // ── State ──
  currentSession: null,
  sessions: [],
  isConnecting: false,
  error: null,

  // ── Actions ──

  async createSession(target) {
    set({ isConnecting: true, error: null });
    try {
      const session = await apiCreateSession({ target });
      setStoredSessionId(session.id);
      set((s) => ({
        currentSession: session,
        sessions: [session, ...s.sessions],
        isConnecting: false,
      }));
      return session;
    } catch (err) {
      set({ isConnecting: false, error: String(err) });
      throw err;
    }
  },

  async loadSession(id) {
    set({ isConnecting: true, error: null });
    try {
      const session = await apiGetSession(id);
      setStoredSessionId(session.id);
      set({ currentSession: session, isConnecting: false });
    } catch (err) {
      set({ isConnecting: false, error: String(err) });
      throw err;
    }
  },

  clearSession() {
    clearStoredSessionId();
    set({ currentSession: null });
  },

  async loadSessions() {
    try {
      const sessions = await apiListSessions();
      set({ sessions });
    } catch {
      // non-fatal
    }
  },

  async deleteSession(id) {
    await apiDeleteSession(id);
    const { currentSession } = get();
    if (currentSession?.id === id) {
      clearStoredSessionId();
    }
    set((s) => ({
      sessions: s.sessions.filter((ss) => ss.id !== id),
      currentSession: s.currentSession?.id === id ? null : s.currentSession,
    }));
  },

  // Re-hydrate from localStorage on startup
  async hydrate() {
    const id = getStoredSessionId();
    if (!id) return;
    try {
      const session = await apiGetSession(id);
      set({ currentSession: session });
    } catch {
      clearStoredSessionId();
    }
  },
}));
