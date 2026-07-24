'use strict';

// Web Worker hosting the sing-vis matching engine. The engine is pure JavaScript
// (engine/*.js) — no WebAssembly on the common path — so it is ready immediately.
// A tiny Go/wasm .srs decoder is loaded lazily by engine/browser.js only when a
// config actually references a binary (.srs) rule set. Running here keeps DoH
// resolution, rule-set fetching and matching off the UI thread.
//
// Message protocol (unchanged from the previous wasm build):
//   main → worker:  { id, request }   request = the analyze payload
//   worker → main:  { id, result }    on success (result = engine.Result)
//                   { id, error }     on failure (error = message string)
//                   { type:'ready' }  once the engine is initialized
//                   { type:'loaderror', error } if engine scripts failed to load

try {
  importScripts('engine/ip.js', 'engine/parse.js', 'engine/engine.js', 'engine/browser.js');
  self.postMessage({ type: 'ready' });
} catch (err) {
  self.postMessage({ type: 'loaderror', error: (err && err.message) || String(err) });
}

self.onmessage = async (e) => {
  const data = e.data || {};
  if (data.id == null) return;
  try {
    const request = data.request || {};
    const deps = self.SingvisBrowser.makeDeps(request);
    const result = await self.SingvisEngine.analyze(request, deps);
    self.postMessage({ id: data.id, result });
  } catch (err) {
    self.postMessage({ id: data.id, error: (err && err.message) || String(err) });
  }
};
