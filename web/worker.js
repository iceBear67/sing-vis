'use strict';

// Web Worker that hosts the sing-vis WebAssembly engine. It loads the Go runtime
// shim + singvis.wasm, keeps the Go program alive, and forwards analyze requests
// to the JS-exported `singvisAnalyze`. Running in a worker keeps the wasm work
// (DoH resolution, rule-set fetching, matching) off the UI thread.
//
// Message protocol:
//   main → worker:  { id, request }   request = the analyze payload
//   worker → main:  { id, result }    on success (result = parsed engine.Result)
//                   { id, error }     on failure (error = message string)
//                   { type:'ready' }  once the wasm engine is initialized
//                   { type:'loaderror', error } if the wasm failed to load

importScripts('wasm_exec.js');

// Resolved by the Go program (via the `singvisReady` callback it invokes in main)
// once `singvisAnalyze` has been registered on the global scope.
let signalStarted;
const started = new Promise((resolve) => { signalStarted = resolve; });
globalThis.singvisReady = () => signalStarted();

const ready = (async () => {
  const go = new Go();
  let instance;
  try {
    // Preferred path; requires the server to send Content-Type: application/wasm.
    const res = await WebAssembly.instantiateStreaming(fetch('singvis.wasm'), go.importObject);
    instance = res.instance;
  } catch (streamErr) {
    // Fallback for static servers that don't set the wasm MIME type.
    const resp = await fetch('singvis.wasm');
    if (!resp.ok) throw new Error('failed to load singvis.wasm (HTTP ' + resp.status + ')');
    const bytes = await resp.arrayBuffer();
    const res = await WebAssembly.instantiate(bytes, go.importObject);
    instance = res.instance;
  }
  // Do NOT await: the Go main blocks forever (select{}) to keep serving calls.
  go.run(instance);
  await started;
})();

ready.then(
  () => self.postMessage({ type: 'ready' }),
  (err) => self.postMessage({ type: 'loaderror', error: (err && err.message) || String(err) })
);

self.onmessage = async (e) => {
  const data = e.data || {};
  if (data.id == null) return;
  try {
    await ready;
    const out = await globalThis.singvisAnalyze(JSON.stringify(data.request || {}));
    self.postMessage({ id: data.id, result: JSON.parse(out) });
  } catch (err) {
    self.postMessage({ id: data.id, error: (err && err.message) || String(err) });
  }
};
