'use strict';

// IndexedDB-backed persistence for profiles and settings — the browser-side
// replacement for the old file store. IndexedDB (not localStorage) is used
// because uploaded .srs rule-set files can exceed localStorage's ~5MB limit.
//
// Shapes match the former Go store exactly:
//   Profile  { id, name, config, inputs, createdAt, updatedAt, ruleSetFiles }
//   Settings { dohServer }
//
// Exposed as window.singvisStorage (app.js is a classic script).

(function () {
  const DB_NAME = 'singvis';
  const DB_VERSION = 2;
  const STORE_PROFILES = 'profiles';
  const STORE_META = 'meta';
  const STORE_BLOBS = 'blobs'; // large binary payloads (e.g. the qqwry.ipdb geo database)
  const SETTINGS_KEY = 'settings';

  const DEFAULT_SETTINGS = {
    dohServer: 'https://1.1.1.1/dns-query',
    geoEnabled: true,
    geoUrl: 'https://cdn.jsdelivr.net/npm/qqwry.ipdb/qqwry.ipdb',
  };

  let dbPromise = null;

  function openDB() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_PROFILES)) {
          db.createObjectStore(STORE_PROFILES, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(STORE_META)) {
          db.createObjectStore(STORE_META);
        }
        if (!db.objectStoreNames.contains(STORE_BLOBS)) {
          db.createObjectStore(STORE_BLOBS);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error('failed to open IndexedDB'));
    });
    return dbPromise;
  }

  // tx runs fn(store) inside a transaction and resolves with `out` (a value fn
  // can set) once the transaction completes.
  async function tx(storeName, mode, fn) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const t = db.transaction(storeName, mode);
      const store = t.objectStore(storeName);
      let out;
      const ret = (v) => { out = v; };
      Promise.resolve(fn(store, ret)).catch(reject);
      t.oncomplete = () => resolve(out);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error || new Error('transaction aborted'));
    });
  }

  function reqPromise(request) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  function newId() {
    // Millisecond timestamp plus a short random suffix to avoid collisions when
    // several profiles are created within the same millisecond.
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  }

  const api = {
    async listProfiles() {
      const list = await tx(STORE_PROFILES, 'readonly', async (store, ret) => {
        ret(await reqPromise(store.getAll()));
      });
      const out = list || [];
      out.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
      return out;
    },

    async getProfile(id) {
      const p = await tx(STORE_PROFILES, 'readonly', async (store, ret) => {
        ret(await reqPromise(store.get(id)));
      });
      if (!p) throw new Error('profile not found');
      return p;
    },

    // saveProfile creates (when profile.id is empty) or updates a profile,
    // assigning id/createdAt/updatedAt the same way the old server did.
    async saveProfile(profile) {
      const now = Date.now();
      const p = Object.assign({}, profile);
      if (!p.id) {
        p.id = newId();
        p.createdAt = now;
      }
      if (!p.createdAt) p.createdAt = now;
      p.updatedAt = now;
      p.ruleSetFiles = p.ruleSetFiles || {};
      await tx(STORE_PROFILES, 'readwrite', (store) => {
        store.put(p);
      });
      return p;
    },

    async deleteProfile(id) {
      await tx(STORE_PROFILES, 'readwrite', (store) => {
        store.delete(id);
      });
    },

    async getSettings() {
      const s = await tx(STORE_META, 'readonly', async (store, ret) => {
        ret(await reqPromise(store.get(SETTINGS_KEY)));
      });
      const merged = Object.assign({}, DEFAULT_SETTINGS, s || {});
      if (!merged.dohServer) merged.dohServer = DEFAULT_SETTINGS.dohServer;
      return merged;
    },

    async saveSettings(settings) {
      const merged = Object.assign({}, DEFAULT_SETTINGS, settings || {});
      if (!merged.dohServer) merged.dohServer = DEFAULT_SETTINGS.dohServer;
      await tx(STORE_META, 'readwrite', (store) => {
        store.put(merged, SETTINGS_KEY);
      });
      return merged;
    },

    defaultSettings() {
      return Object.assign({}, DEFAULT_SETTINGS);
    },

    // Large binary payloads (ArrayBuffer), keyed by an arbitrary string. Used to
    // cache the ~37 MB geo database so it is downloaded only once.
    async getBlob(key) {
      return tx(STORE_BLOBS, 'readonly', async (store, ret) => {
        ret(await reqPromise(store.get(key)));
      });
    },

    async putBlob(key, value) {
      await tx(STORE_BLOBS, 'readwrite', (store) => {
        store.put(value, key);
      });
    },
  };

  window.singvisStorage = api;
})();
