#!/usr/bin/env node

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import {
  link,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

import {
  PrivacyPoolSDK,
  calculateContext,
  generateMerkleProof,
  getCommitment,
} from "@0xbow/privacy-pools-core-sdk";
import { poseidon } from "maci-crypto/build/ts/hashing.js";
import {
  createPublicClient,
  decodeAbiParameters,
  encodeFunctionData,
  formatEther,
  getAddress,
  http,
  keccak256,
  toHex,
} from "viem";
import { mainnet } from "viem/chains";

const POOL = "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb";
const ENTRYPOINT = "0x6818809eefce719e480a7526d76bd3e561526b46";
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DEFAULT_RPC = "https://ethereum-rpc.publicnode.com";
const ASP_LEAVES = "https://api.0xbow.io/1/public/mt-leaves";
const NATIVE_ASSET = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
const PRIVATE_INPUT_TIMEOUT_MS = 5 * 60 * 1000;
const PRIVATE_INPUT_MAX_BYTES = 1024;
const ARTIFACT_HASHES = Object.freeze({
  "withdraw.wasm": "36cda22791def3d520a55c0fc808369cd5849532a75fab65686e666ed3d55c10",
  "withdraw.vkey": "666bd0983b20c1611543b04f7712e067fbe8cad69f07ada8a310837ff398d21e",
  "withdraw.zkey": "2a893b42174c813566e5c40c715a8b90cd49fc4ecf384e3a6024158c3d6de677",
});

const poolAbi = [
  { type: "function", name: "SCOPE", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "nullifierHashes", stateMutability: "view", inputs: [{ type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "currentRoot", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "currentTreeDepth", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  {
    type: "function",
    name: "withdraw",
    stateMutability: "nonpayable",
    inputs: [
      { type: "tuple", components: [{ name: "processooor", type: "address" }, { name: "data", type: "bytes" }] },
      {
        type: "tuple",
        components: [
          { name: "pA", type: "uint256[2]" },
          { name: "pB", type: "uint256[2][2]" },
          { name: "pC", type: "uint256[2]" },
          { name: "pubSignals", type: "uint256[8]" },
        ],
      },
    ],
    outputs: [],
  },
];
const entrypointAbi = [
  { type: "function", name: "latestRoot", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "scopeToPool", stateMutability: "view", inputs: [{ type: "uint256" }], outputs: [{ type: "address" }] },
  {
    type: "function",
    name: "relay",
    stateMutability: "nonpayable",
    inputs: [
      { type: "tuple", components: [{ name: "processooor", type: "address" }, { name: "data", type: "bytes" }] },
      {
        type: "tuple",
        components: [
          { name: "pA", type: "uint256[2]" },
          { name: "pB", type: "uint256[2][2]" },
          { name: "pC", type: "uint256[2]" },
          { name: "pubSignals", type: "uint256[8]" },
        ],
      },
      { name: "_scope", type: "uint256" },
    ],
    outputs: [],
  },
];
const WITHDRAWN_TOPIC = keccak256(toHex("Withdrawn(address,uint256,uint256,uint256)"));
const WITHDRAWAL_RELAYED_TOPIC = keccak256(toHex("WithdrawalRelayed(address,address,address,uint256,uint256)"));
const QUOTE_SAFETY_MS = 15_000;
const AMBIGUOUS_RETRY_DELAY_MS = 5 * 60 * 1000;

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function stringify(value) {
  return JSON.stringify(value, (_, item) => typeof item === "bigint" ? item.toString() : item, 2);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    assert(key?.startsWith("--") && rest[index + 1] !== undefined, `invalid argument: ${key ?? "<missing>"}`);
    options[key.slice(2)] = rest[index + 1];
  }
  return { command, options };
}

function required(options, key) {
  const value = options[key];
  assert(value, `missing --${key}`);
  return value;
}

function bloomHome(options) {
  return resolve(options.home ?? process.env.BLOOM_HOME ?? `${homedir()}/.bloom`);
}

async function activeDataRoot(home) {
  const owner = JSON.parse(await readFile(`${home}/petals/store/owners/privacy-pools.json`, "utf8"));
  assert(/^[0-9a-f]{64}$/.test(owner.hash), "invalid active privacy-pools package hash");
  return `${home}/petals/data/${owner.hash}`;
}

function safeSegment(value, label) {
  assert(/^[A-Za-z0-9._-]{1,128}$/.test(value) && value !== "." && value !== "..", `unsafe ${label}`);
  return value;
}

const PRIVATE_INPUT_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#f4efe6">
  <meta name="referrer" content="no-referrer">
  <title>/bloom — Private relay destination</title>
  <link rel="icon" href="/bloom-primary.svg" type="image/svg+xml">
  <link rel="stylesheet" href="/private-input.css">
</head>
<body>
  <main class="page">
    <header class="brand" aria-label="Bloom walletFS">
      <img src="/bloom-primary.svg" width="30" height="30" alt="">
      <span><strong>/bloom</strong> walletFS</span>
    </header>
    <div class="layout">
      <section class="intro" aria-labelledby="page-title">
        <p class="eyebrow">Private Petal input</p>
        <h1 id="page-title">Enter it here.</h1>
        <p class="lede">This destination goes only to the local Privacy Pools companion. It never appears in chat, commands, logs, or VFS state.</p>
        <div class="trust">
          <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg><div><strong>Local and short-lived</strong>The form listens only on this device and closes after one valid address.</div></div>
          <div class="trust-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 3 20 7v5c0 4.6-3.1 7.5-8 9-4.9-1.5-8-4.4-8-9V7l8-4Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></svg><div><strong>No signature here</strong>The running companion proceeds after entry, but this form does not create a passkey or transaction signature.</div></div>
        </div>
      </section>
      <section class="panel">
        <header class="panel-header"><p class="panel-kicker">Privacy Pools</p><h2 class="panel-title">Withdrawal recipient</h2><p id="message" role="status">Loading request…</p></header>
        <section class="review" aria-label="Transfer context">
          <dl>
            <div><dt>Network</dt><dd id="network"></dd></div>
            <div><dt>Asset</dt><dd id="asset"></dd></div>
            <div><dt>Amount</dt><dd id="amountEth"></dd></div>
            <div><dt>Amount (wei)</dt><dd id="amountWei"></dd></div>
            <div><dt>Source note</dt><dd id="source"></dd></div>
            <div><dt>Relayer</dt><dd id="relayer"></dd></div>
            <div><dt>Maximum fee</dt><dd id="maxFee"></dd></div>
          </dl>
        </section>
        <form id="form">
          <fieldset><legend>Ethereum recipient</legend><label>Address<input id="recipient" name="recipient" type="text" inputmode="text" required autocomplete="off" spellcheck="false" placeholder="0x…" pattern="0x[0-9a-fA-F]{40}"></label><p>Check the network, amount, and source above. The address is retained only in the companion's private retry journal.</p></fieldset>
          <div class="actions"><button id="submit" type="submit" disabled>Use privately</button><button id="cancel" class="secondary" type="button">Cancel</button></div>
        </form>
      </section>
    </div>
  </main>
<script src="/private-input.js"></script>
</body>
</html>`;

const PRIVATE_INPUT_CSS = `:root{--paper:#f4efe6;--surface:#faf7f1;--ink:#15130f;--ink-2:#342d24;--muted:#706757;--rule:#d5c9b6;--rule-2:#c4b59d;--leaf:#526f51;--accent:#8a2a3a;--accent-deep:#5e1a26;--success:#355f47;--error:#7a2230;--serif:"Iowan Old Style","Palatino Linotype",Georgia,serif;--sans:"Avenir Next",Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--mono:"SFMono-Regular",Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box}html{min-height:100%;background:var(--paper);color:var(--ink);-webkit-text-size-adjust:100%}
body{min-height:100vh;margin:0;font-family:var(--sans);font-size:16px;line-height:1.5;-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(115deg,rgba(255,255,255,.68),transparent 38%),linear-gradient(180deg,rgba(82,111,81,.08),transparent 50%),linear-gradient(0deg,rgba(138,42,58,.055),transparent 38%)}
body::after{content:"";position:fixed;width:440px;height:440px;right:-180px;top:-190px;border:1px solid rgba(138,42,58,.13);border-radius:50%;box-shadow:0 0 0 72px rgba(138,42,58,.025),0 0 0 144px rgba(82,111,81,.02);pointer-events:none}
.page{position:relative;z-index:1;width:min(1080px,100%);margin:0 auto;padding:28px clamp(20px,4vw,56px) 56px}.brand{display:inline-flex;align-items:center;gap:10px;color:var(--ink);font-family:var(--mono);font-size:12px;text-transform:uppercase}.brand strong{color:var(--accent-deep)}.brand img{display:block;width:30px;height:30px}
.layout{display:grid;grid-template-columns:minmax(260px,.72fr) minmax(460px,1fr);gap:clamp(44px,7vw,92px);align-items:start;margin-top:48px}.intro{position:sticky;top:28px;padding-top:12px}.eyebrow{margin:0 0 15px;color:var(--accent);font-family:var(--mono);font-size:11px;letter-spacing:.07em;text-transform:uppercase}
h1{margin:0;font-family:var(--serif);font-size:clamp(48px,6vw,72px);font-style:italic;font-weight:400;line-height:.96;letter-spacing:-.025em}.lede{margin:22px 0 0;color:var(--ink-2);font-size:17px}.trust{display:grid;gap:14px;margin-top:34px;padding-top:22px;border-top:1px solid var(--rule);color:var(--muted);font-size:13px}.trust strong{display:block;color:var(--ink-2);font-size:14px}.trust-item{display:grid;grid-template-columns:22px 1fr;gap:10px}.trust-item svg{width:19px;color:var(--leaf)}
.panel{overflow:hidden;border:1px solid var(--rule-2);border-radius:18px;background:rgba(250,247,241,.92);box-shadow:0 24px 70px rgba(52,45,36,.09),0 2px 8px rgba(52,45,36,.04);backdrop-filter:blur(12px)}.panel-header{padding:27px 30px 23px;border-bottom:1px solid var(--rule);background:rgba(236,228,214,.38)}.panel-kicker{margin:0 0 6px;color:var(--muted);font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase}.panel-title{margin:0;font-family:var(--serif);font-size:30px;font-weight:400}#message{margin:7px 0 0;color:var(--muted);font-size:13px}
.review{padding:24px 30px;border-bottom:1px solid var(--rule)}.review dl{display:grid;gap:10px;margin:0}.review dl div{display:grid;grid-template-columns:minmax(110px,.42fr) 1fr;gap:16px;padding-bottom:10px;border-bottom:1px solid var(--rule)}.review dl div:last-child{padding-bottom:0;border-bottom:0}.review dt{color:var(--muted);font-family:var(--mono);font-size:10px;letter-spacing:.05em;text-transform:uppercase}.review dd{margin:0;color:var(--ink-2);font-family:var(--mono);font-size:12px;overflow-wrap:anywhere}
fieldset{margin:0;padding:24px 30px;border:0;border-bottom:1px solid var(--rule)}legend{padding:0;color:var(--ink);font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase}label{display:grid;gap:5px;margin-top:13px;color:var(--ink-2);font-size:13px}input{width:100%;padding:11px 12px;border:1px solid var(--rule-2);border-radius:8px;background:#fffdf9;color:var(--ink);font:13px/1.45 var(--mono)}input:focus{border-color:var(--accent);outline:3px solid rgba(138,42,58,.1)}fieldset p{color:var(--muted);font-size:12px}.actions{display:grid;grid-template-columns:1fr auto;gap:10px;padding:26px 30px 30px;background:rgba(236,228,214,.22)}button{min-height:49px;padding:12px 18px;border:0;border-radius:9px;background:var(--accent);color:var(--paper);font:500 12px var(--mono);cursor:pointer;box-shadow:0 8px 20px rgba(94,26,38,.17);transition:transform .16s,background .16s}button:hover:not(:disabled){transform:translateY(-1px);background:var(--accent-deep)}button:disabled{opacity:.48;cursor:wait;box-shadow:none}button.secondary{border:1px solid var(--rule-2);background:transparent;color:var(--ink-2);box-shadow:none}
@media(max-width:820px){.layout{grid-template-columns:1fr;gap:30px;margin-top:32px}.intro{position:static}.trust{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.page{padding:19px 14px 28px}h1{font-size:46px}.panel{border-radius:14px}.panel-header,.review,fieldset,.actions{padding-left:20px;padding-right:20px}.actions{grid-template-columns:1fr}.trust{grid-template-columns:1fr}}@media(prefers-reduced-motion:reduce){*{transition:none!important}}`;

const BLOOM_PRIMARY_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024"><g stroke-linejoin="round" stroke-linecap="round"><path d="M 24.58 0 C 96.09 141.31 209.14 141.31 282.62 0" fill="none" stroke="#7a2230" stroke-width="30" transform="translate(512 512) rotate(-72.500) scale(1.24)"></path><path d="M 24.58 0 C 96.09 141.31 209.14 141.31 282.62 0 C 209.14 -141.31 96.09 -141.31 24.58 0 Z" fill="#9d2d3f" transform="translate(512 512) rotate(-12.500) scale(1.24)"></path><path d="M 24.58 0 C 96.09 141.31 209.14 141.31 282.62 0 C 209.14 -141.31 96.09 -141.31 24.58 0 Z" fill="none" stroke="#7a2230" stroke-width="30" transform="translate(512 512) rotate(47.500) scale(1.24)"></path><path d="M 24.58 0 C 96.09 141.31 209.14 141.31 282.62 0 C 209.14 -141.31 96.09 -141.31 24.58 0 Z" fill="#9d2d3f" transform="translate(512 512) rotate(107.500) scale(1.24)"></path><path d="M 24.58 0 C 96.09 141.31 209.14 141.31 282.62 0 C 209.14 -141.31 96.09 -141.31 24.58 0 Z" fill="none" stroke="#7a2230" stroke-width="30" transform="translate(512 512) rotate(167.500) scale(1.24)"></path><path d="M 24.58 0 C 96.09 141.31 209.14 141.31 282.62 0 C 209.14 -141.31 96.09 -141.31 24.58 0 Z" fill="#9d2d3f" transform="translate(512 512) rotate(227.500) scale(1.24)"></path><path d="M 282.62 0 C 209.14 -141.31 96.09 -141.31 24.58 0" fill="none" stroke="#7a2230" stroke-width="30" transform="translate(512 512) rotate(-72.500) scale(1.24)"></path></g></svg>`;

const PRIVATE_INPUT_JS = `(() => {
  const token = location.pathname.split("/").pop();
  history.replaceState(null, "", "/");
  const headers = { "X-Private-Input-Token": token };
  const message = document.getElementById("message");
  const submit = document.getElementById("submit");
  const cancel = document.getElementById("cancel");
  fetch("/context", { headers }).then((response) => {
    if (!response.ok) throw new Error("expired");
    return response.json();
  }).then((context) => {
    for (const key of ["network", "asset", "amountEth", "amountWei", "source", "relayer", "maxFee"]) {
      document.getElementById(key).textContent = context[key];
    }
    message.textContent = "Review the transfer, then enter its destination. No passkey or signature is requested.";
    submit.disabled = false;
  }).catch(() => { message.textContent = "This form expired. Run the helper again."; });
  document.getElementById("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    try {
      const response = await fetch("/submit", {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ recipient: document.getElementById("recipient").value }),
      });
      message.textContent = response.ok ? "Destination accepted. You may close this tab." : "Invalid address. Check it and try again.";
      if (!response.ok) {
        submit.disabled = false;
        return;
      }
      document.getElementById("recipient").value = "";
      document.getElementById("recipient").disabled = true;
    } catch {
      message.textContent = "This form expired. Run the helper again.";
    }
  });
  cancel.addEventListener("click", async () => {
    submit.disabled = true;
    cancel.disabled = true;
    try {
      await fetch("/cancel", { method: "POST", headers });
      message.textContent = "Cancelled. You may close this tab.";
    } catch {
      message.textContent = "This form expired. You may close this tab.";
    }
  });
})();`;

function privateInputHeaders(response, contentType) {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Content-Type", contentType);
}

function tokenMatches(request, token) {
  const supplied = request.headers["x-private-input-token"];
  if (typeof supplied !== "string") return false;
  const left = Buffer.from(supplied);
  const right = Buffer.from(token);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function boundedJson(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > PRIVATE_INPUT_MAX_BYTES) fail("private input request is too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function launchBrowser(url) {
  const command = process.platform === "darwin" ? "/usr/bin/open" : process.platform === "linux" ? "xdg-open" : null;
  assert(command, "automatic browser launch is unsupported on this platform");
  await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, [url], { detached: true, stdio: "ignore" });
    child.once("error", rejectPromise);
    child.once("spawn", () => {
      child.unref();
      resolvePromise();
    });
  });
}

export async function collectPrivateRecipient({ amountWei, source, relayer, maxFeeBps, openBrowser = launchBrowser, timeoutMs = PRIVATE_INPUT_TIMEOUT_MS }) {
  assert(/^\d+$/.test(amountWei) && BigInt(amountWei) > 0n, "private relay amount is invalid");
  assert(/^\d+$/.test(maxFeeBps) && BigInt(maxFeeBps) <= 10_000n, "private relay fee ceiling is invalid");
  const token = randomBytes(32).toString("base64url");
  const feePercent = Number(maxFeeBps) / 100;
  const context = {
    network: "Ethereum mainnet",
    asset: "ETH",
    amountEth: `${formatEther(BigInt(amountWei))} ETH`,
    amountWei,
    source,
    relayer,
    maxFee: `${maxFeeBps} bps (${feePercent.toLocaleString("en-US", { maximumFractionDigits: 2 })}%)`,
  };

  return await new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let accepted = false;
    let timer;
    const finish = (error, recipient) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      server.close(() => error ? rejectPromise(error) : resolvePromise(recipient));
      server.closeIdleConnections();
    };
    const server = createServer(async (request, response) => {
      try {
        const boundAddress = server.address();
        const expectedHost = boundAddress && typeof boundAddress !== "string"
          ? `127.0.0.1:${boundAddress.port}`
          : null;
        assert(request.headers.host === expectedHost, "private input host mismatch");
        if (request.method === "GET" && request.url === `/private-input/${token}`) {
          privateInputHeaders(response, "text/html; charset=utf-8");
          response.end(PRIVATE_INPUT_HTML);
          return;
        }
        if (request.method === "GET" && request.url === "/private-input.js") {
          privateInputHeaders(response, "text/javascript; charset=utf-8");
          response.end(PRIVATE_INPUT_JS);
          return;
        }
        if (request.method === "GET" && request.url === "/private-input.css") {
          privateInputHeaders(response, "text/css; charset=utf-8");
          response.end(PRIVATE_INPUT_CSS);
          return;
        }
        if (request.method === "GET" && request.url === "/bloom-primary.svg") {
          privateInputHeaders(response, "image/svg+xml");
          response.end(BLOOM_PRIMARY_SVG);
          return;
        }
        if (request.method === "GET" && request.url === "/context" && tokenMatches(request, token)) {
          privateInputHeaders(response, "application/json; charset=utf-8");
          response.end(JSON.stringify(context));
          return;
        }
        if (request.method === "POST" && request.url === "/submit" && tokenMatches(request, token)) {
          const address = server.address();
          const origin = address && `http://127.0.0.1:${address.port}`;
          assert(request.headers.origin === origin, "private input origin mismatch");
          assert(request.headers["content-type"]?.split(";", 1)[0] === "application/json", "private input must be JSON");
          const body = await boundedJson(request);
          assert(typeof body.recipient === "string", "private recipient is missing");
          const recipient = getAddress(body.recipient.trim());
          assert(recipient !== "0x0000000000000000000000000000000000000000", "private recipient cannot be the zero address");
          assert(!accepted, "private input was already accepted");
          accepted = true;
          privateInputHeaders(response, "text/plain; charset=utf-8");
          response.statusCode = 204;
          response.end(() => finish(null, recipient));
          return;
        }
        if (request.method === "POST" && request.url === "/cancel" && tokenMatches(request, token)) {
          const address = server.address();
          const origin = address && `http://127.0.0.1:${address.port}`;
          assert(request.headers.origin === origin, "private input origin mismatch");
          assert(!accepted, "private input was already accepted");
          accepted = true;
          privateInputHeaders(response, "text/plain; charset=utf-8");
          response.statusCode = 204;
          response.end(() => finish(new Error("private destination entry cancelled")));
          return;
        }
        response.statusCode = 404;
        response.end();
      } catch {
        privateInputHeaders(response, "text/plain; charset=utf-8");
        response.statusCode = 400;
        response.end("invalid private input");
      }
    });
    server.once("error", (error) => finish(error));
    server.listen(0, "127.0.0.1", async () => {
      const address = server.address();
      try {
        assert(address && typeof address !== "string", "private input server did not bind a TCP port");
        timer = setTimeout(() => finish(new Error("private destination form expired; rerun the helper")), timeoutMs);
        await openBrowser(`http://127.0.0.1:${address.port}/private-input/${token}`);
      } catch (error) {
        finish(error);
      }
    });
  });
}

export async function atomicWrite(path, bytes, { exclusive = false, mode = 0o600 } = {}) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  let file;
  try {
    file = await open(temporary, "wx", mode);
    await file.writeFile(bytes);
    await file.sync();
    await file.chmod(mode);
  } finally {
    await file?.close();
  }
  try {
    if (exclusive) {
      // link() atomically fails with EEXIST if the destination already
      // exists. Unlike the previous access()-then-rename() sequence, there
      // is no window between the check and the act for a second concurrent
      // writer to slip in: the filesystem itself makes EEXIST authoritative,
      // and rename() (used below for the non-exclusive case) would have
      // silently replaced an existing destination instead of failing.
      try {
        await link(temporary, path);
      } catch (error) {
        if (error?.code === "EEXIST") fail(`refusing to overwrite ${path}`);
        throw error;
      }
    } else {
      await rename(temporary, path);
    }
  } finally {
    if (exclusive) {
      // link() leaves the temp file in place on both success and failure
      // (it doesn't consume it the way rename() does); always clean it up.
      await unlink(temporary).catch((error) => {
        if (error?.code !== "ENOENT") throw error;
      });
    }
  }
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function readJsonIfExists(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export async function writeIdenticalOrCreate(path, value, options = {}) {
  const existing = await readJsonIfExists(path);
  if (existing !== null) {
    assert(JSON.stringify(existing) === JSON.stringify(value), `refusing to replace different durable state at ${path}`);
    return;
  }
  await atomicWrite(path, Buffer.from(`${JSON.stringify(value)}\n`), { ...options, exclusive: true });
}

async function passphrase(path) {
  const metadata = await stat(path);
  assert((metadata.mode & 0o077) === 0, "passphrase file must not be accessible by group or others");
  const value = (await readFile(path, "utf8")).replace(/[\r\n]+$/, "");
  assert(value.length >= 12, "passphrase must contain at least 12 characters");
  return value;
}

const ENVELOPE_SCHEMA_V1 = "bloom.privacy-pools.encrypted-note.v1";
const ENVELOPE_SCHEMA_V2 = "bloom.privacy-pools.encrypted-note.v2";
const ENVELOPE_STRUCTURAL_FIELDS = new Set([
  "schema", "cipher", "kdf", "iv", "tag", "ciphertext", "plaintext_sha256",
]);

// v2 envelopes bind their own routing metadata (kind/wallet/id/parent_id) as
// AES-GCM Additional Authenticated Data. Those fields are stored as plaintext
// JSON alongside the ciphertext (so backups stay inspectable without the
// password), but restore uses them to decide *where on disk to write* — so
// without AAD, anyone with write access to a backup file (no password
// needed) could edit `wallet`/`id`/`kind` and have decryption succeed
// against the unmodified ciphertext, retargeting a restore. Binding them as
// AAD makes any such edit fail GCM authentication before those fields are
// ever trusted.
function envelopeAad(metadata) {
  const keys = Object.keys(metadata).sort();
  return Buffer.from(JSON.stringify(Object.fromEntries(keys.map((key) => [key, metadata[key]]))));
}

function envelopeMetadata(envelope) {
  return Object.fromEntries(
    Object.entries(envelope).filter(([key]) => !ENVELOPE_STRUCTURAL_FIELDS.has(key)),
  );
}

export function encryptEnvelope(plaintext, password, metadata) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(password, salt, 32, { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(envelopeAad(metadata));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    schema: ENVELOPE_SCHEMA_V2,
    cipher: "aes-256-gcm",
    kdf: { name: "scrypt", N: 131072, r: 8, p: 1, salt: salt.toString("base64") },
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    plaintext_sha256: createHash("sha256").update(plaintext).digest("hex"),
    ...metadata,
  };
}

export function decryptEnvelope(envelope, password) {
  assert(
    envelope.schema === ENVELOPE_SCHEMA_V1 || envelope.schema === ENVELOPE_SCHEMA_V2,
    "unsupported backup schema",
  );
  const salt = Buffer.from(envelope.kdf.salt, "base64");
  const key = scryptSync(password, salt, 32, {
    N: envelope.kdf.N,
    r: envelope.kdf.r,
    p: envelope.kdf.p,
    maxmem: 256 * 1024 * 1024,
  });
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
  if (envelope.schema === ENVELOPE_SCHEMA_V2) {
    decipher.setAAD(envelopeAad(envelopeMetadata(envelope)));
  }
  // v1 envelopes predate AAD binding. They cannot be retroactively
  // authenticated without the password (which is required to re-encrypt,
  // not merely to read), so existing v0.1.3 backups keep decrypting exactly
  // as before — their routing metadata remains unauthenticated. All new
  // backups are v2.
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]);
  const digest = Buffer.from(createHash("sha256").update(plaintext).digest("hex"));
  const expected = Buffer.from(envelope.plaintext_sha256);
  assert(digest.length === expected.length && timingSafeEqual(digest, expected), "backup plaintext hash mismatch");
  return plaintext;
}

export async function verifiedBackup(value, output, password, metadata) {
  const plaintext = Buffer.from(`${JSON.stringify(value)}\n`);
  const existing = await readJsonIfExists(output);
  if (existing !== null) {
    for (const [key, expected] of Object.entries(metadata)) {
      assert(existing[key] === expected, `existing backup has different ${key}`);
    }
    const recovered = decryptEnvelope(existing, password);
    assert(
      plaintext.length === recovered.length && timingSafeEqual(plaintext, recovered),
      "existing backup contains different replacement material",
    );
    return existing.plaintext_sha256;
  }
  const envelope = encryptEnvelope(plaintext, password, metadata);
  const encoded = Buffer.from(`${stringify(envelope)}\n`);
  await atomicWrite(output, encoded, { exclusive: true });
  const reread = JSON.parse(await readFile(output, "utf8"));
  const recovered = decryptEnvelope(reread, password);
  assert(timingSafeEqual(plaintext, recovered), "backup verification failed");
  return envelope.plaintext_sha256;
}

function publicStatus(note) {
  const { nullifier: _nullifier, secret: _secret, ...status } = note;
  return status;
}

async function backupCommand(options) {
  const wallet = safeSegment(required(options, "wallet"), "wallet");
  const id = safeSegment(required(options, "id"), "id");
  const output = resolve(required(options, "out"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const root = await activeDataRoot(bloomHome(options));
  const notePath = `${root}/secrets/privacy-pools/notes/${wallet}/${id}`;
  const statePath = `${root}/state/privacy-pools/deposits/${wallet}/${id}`;
  const note = JSON.parse(await readFile(notePath, "utf8"));
  const digest = await verifiedBackup(note, output, password, { kind: "deposit", wallet, id });
  note.backup_verified = true;
  await atomicWrite(notePath, Buffer.from(`${JSON.stringify(note)}\n`));
  await atomicWrite(statePath, Buffer.from(`${JSON.stringify(publicStatus(note))}\n`));
  console.log(stringify({ backupVerified: true, wallet, id, output, plaintextSha256: digest }));
}

function validateNoteSecrets(note) {
  const nullifier = BigInt(note.nullifier);
  const secret = BigInt(note.secret);
  const precommitment = BigInt(poseidon([nullifier, secret]));
  assert(precommitment === BigInt(note.precommitment), "note secrets do not reproduce precommitment");
}

export async function restoreCommand(options) {
  const input = resolve(required(options, "in"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const envelope = JSON.parse(await readFile(input, "utf8"));
  const plaintext = decryptEnvelope(envelope, password);
  const value = JSON.parse(plaintext.toString("utf8"));
  if (envelope.schema === ENVELOPE_SCHEMA_V1) {
    // v1 envelopes predate AAD binding: their kind/wallet/id fields are
    // plaintext, unauthenticated, and restoreCommand uses exactly those
    // fields to decide where on disk to write. Decryption alone (which
    // still works, for backward compatibility with existing v0.1.3-era
    // backups) proves the password is correct; it proves nothing about
    // whether those routing fields were tampered with after encryption.
    // Require the operator to independently assert, out of band, the
    // wallet/id/kind they actually intend to restore to -- restore then
    // fails closed unless that matches what the envelope claims, rather
    // than silently trusting the file. kind matters as much as wallet/id:
    // it alone selects the destination directory (notes/ vs replacements/)
    // and which validation runs (validateNoteSecrets only applies to
    // "deposit"), so flipping it unauthenticated could route a restore
    // into the wrong secret store or skip a check meant to apply to it.
    const expectedWallet = safeSegment(required(options, "trust-legacy-wallet"), "trust-legacy-wallet");
    const expectedId = safeSegment(required(options, "trust-legacy-id"), "trust-legacy-id");
    const expectedKind = required(options, "trust-legacy-kind");
    assert(
      envelope.wallet === expectedWallet && envelope.id === expectedId && envelope.kind === expectedKind,
      "v1 backup's unauthenticated wallet/id/kind do not match --trust-legacy-wallet/--trust-legacy-id/--trust-legacy-kind; " +
        "refusing to restore without an explicit, matching operator assertion",
    );
  }
  const root = await activeDataRoot(bloomHome(options));
  if (envelope.kind === "deposit") {
    const wallet = safeSegment(envelope.wallet, "wallet");
    const id = safeSegment(envelope.id, "id");
    validateNoteSecrets(value);
    value.backup_verified = true;
    const notePath = `${root}/secrets/privacy-pools/notes/${wallet}/${id}`;
    const statePath = `${root}/state/privacy-pools/deposits/${wallet}/${id}`;
    try {
      const existing = JSON.parse(await readFile(notePath, "utf8"));
      assert(existing.nullifier === value.nullifier && existing.secret === value.secret, "refusing to replace a different existing note");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await atomicWrite(notePath, Buffer.from(`${JSON.stringify(value)}\n`));
    await atomicWrite(statePath, Buffer.from(`${JSON.stringify(publicStatus(value))}\n`));
  } else if (envelope.kind === "replacement") {
    const wallet = safeSegment(envelope.wallet, "wallet");
    const id = safeSegment(envelope.id, "replacement id");
    value.backup_verified = true;
    const replacementPath = `${root}/secrets/privacy-pools/replacements/${wallet}/${id}`;
    try {
      const existing = JSON.parse(await readFile(replacementPath, "utf8"));
      assert(existing.nullifier === value.nullifier && existing.secret === value.secret, "refusing to replace a different existing replacement note");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await atomicWrite(replacementPath, Buffer.from(`${JSON.stringify(value)}\n`));
  } else {
    fail("backup has unknown note kind");
  }
  console.log(stringify({ restored: true, kind: envelope.kind, wallet: envelope.wallet, id: envelope.id }));
}

function fieldElement() {
  let value = 0n;
  while (value === 0n) value = BigInt(`0x${randomBytes(32).toString("hex")}`) % FIELD;
  return value;
}

function treeDepth(length) {
  assert(Number.isSafeInteger(length) && length > 0, "tree must contain leaves");
  return BigInt(Math.ceil(Math.log2(length)));
}

function asHex(value) {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function progress(phase, details = {}) {
  console.error(stringify({
    petal: "privacy-pools",
    command: "prepare",
    phase,
    at: new Date().toISOString(),
    ...details,
  }));
}

function privateProgress(phase, details = {}) {
  const terminal = phase === "complete";
  console.error(stringify({
    petal: "privacy-pools",
    command: "relay-private",
    status: terminal ? "complete" : "working",
  }));
}

function formatProof(withdrawalProof) {
  const { proof, publicSignals } = withdrawalProof;
  return {
    pA: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pB: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    pC: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
    pubSignals: publicSignals.map(BigInt),
  };
}

export function validateRelayQuote(quote, { recipient, amount, maxFeeBPS, now = Date.now() }) {
  const commitment = quote?.feeCommitment;
  assert(commitment?.withdrawalData && commitment?.signedRelayerCommitment, "relayer quote omitted its signed fee commitment");
  assert(Number.isSafeInteger(Number(commitment.expiration)) && Number(commitment.expiration) > now, "relayer quote is already expired");
  assert(commitment.asset?.toLowerCase() === NATIVE_ASSET.toLowerCase(), "relayer fee commitment names another asset");
  assert(BigInt(commitment.amount) === amount, "relayer fee commitment amount mismatch");
  assert(commitment.extraGas === false, "unexpected extra-gas quote");
  const [encodedRecipient, feeRecipient, encodedFeeBPS] = decodeAbiParameters(
    [{ type: "address" }, { type: "address" }, { type: "uint256" }],
    commitment.withdrawalData,
  );
  assert(encodedRecipient.toLowerCase() === recipient.toLowerCase(), "signed withdrawal data contains another recipient");
  assert(!/^0x0{40}$/i.test(feeRecipient), "signed withdrawal data has a zero fee recipient");
  assert(encodedFeeBPS === BigInt(quote.feeBPS), "quoted fee does not match signed withdrawal data");
  assert(encodedFeeBPS <= maxFeeBPS, "relayer fee exceeds max-fee-bps");
  return { feeBPS: encodedFeeBPS, feeRecipient, withdrawalData: commitment.withdrawalData };
}

export function redactPrivateReplacementNote(note) {
  const { nullifier: _nullifier, secret: _secret, tx, ...publicNote } = note;
  const { tx_hash: _txHash, ...publicTx } = tx ?? {};
  return { ...publicNote, tx: publicTx };
}

class LocalWithdrawCircuits {
  constructor(directory) {
    this.directory = directory;
    this.cache = new Map();
  }
  async artifact(name) {
    if (this.cache.has(name)) return this.cache.get(name);
    const data = await readFile(`${this.directory}/${name}`);
    const digest = createHash("sha256").update(data).digest("hex");
    assert(digest === ARTIFACT_HASHES[name], `artifact integrity mismatch: ${name}`);
    const artifact = new Uint8Array(data);
    this.cache.set(name, artifact);
    return artifact;
  }
  async preload() { await Promise.all(Object.keys(ARTIFACT_HASHES).map((name) => this.artifact(name))); }
  async getWasm(name) { assert(name === "withdraw", `unexpected circuit ${name}`); return this.artifact("withdraw.wasm"); }
  async getProvingKey(name) { assert(name === "withdraw", `unexpected circuit ${name}`); return this.artifact("withdraw.zkey"); }
  async getVerificationKey(name) { assert(name === "withdraw", `unexpected circuit ${name}`); return this.artifact("withdraw.vkey"); }
}

async function verifyArtifactsCommand(options) {
  const directory = resolve(required(options, "artifacts"));
  const circuits = new LocalWithdrawCircuits(directory);
  for (const name of Object.keys(ARTIFACT_HASHES)) {
    await circuits.artifact(name);
  }
  console.log(stringify({
    artifactsVerified: true,
    directory,
    sha256: ARTIFACT_HASHES,
    sdkVersion: "1.4.0",
  }));
}

function resolveSigningAddress(wallet, bloomBinary, home) {
  const result = spawnSync(bloomBinary, ["--home", home, "wallet", "address", wallet], { encoding: "utf8" });
  assert(result.status === 0, `could not resolve signing wallet: ${result.stderr.trim()}`);
  const address = result.stdout.trim();
  assert(/^0x[0-9a-fA-F]{40}$/.test(address), "Bloom returned an invalid wallet address");
  return address;
}

async function prepareCommand(options) {
  progress("starting");
  const noteWallet = safeSegment(required(options, "note-wallet"), "note wallet");
  const id = safeSegment(required(options, "id"), "id");
  const signingWallet = safeSegment(required(options, "signing-wallet"), "signing wallet");
  const replacementId = safeSegment(required(options, "replacement-id"), "replacement id");
  assert(id !== replacementId, "replacement id must differ from the existing note id");
  const output = resolve(required(options, "out"));
  const replacementBackup = resolve(required(options, "replacement-backup"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const artifacts = resolve(required(options, "artifacts"));
  const home = bloomHome(options);
  const root = await activeDataRoot(home);
  const note = JSON.parse(await readFile(`${root}/secrets/privacy-pools/notes/${noteWallet}/${id}`, "utf8"));
  const state = JSON.parse(await readFile(`${root}/state/privacy-pools/deposits/${noteWallet}/${id}`, "utf8"));
  Object.assign(note, state);
  validateNoteSecrets(note);
  assert(note.backup_verified === true, "existing note has no verified encrypted backup");
  assert(note.spent !== true, "existing note is already marked spent");
  for (const field of ["value", "label", "commitment"]) assert(note[field], `deposit is missing reconciled ${field}`);
  progress("note-validated");

  const processooor = options.processooor
    ?? resolveSigningAddress(
      signingWallet,
      options["bloom-bin"] ?? process.env.BLOOM_BIN ?? "bloom",
      home,
    );
  assert(/^0x[0-9a-fA-F]{40}$/.test(processooor), "invalid processooor address");
  const rpcUrl = options.rpc ?? DEFAULT_RPC;
  const client = createPublicClient({ chain: mainnet, transport: http(rpcUrl) });
  progress("reading-contract-roots");
  const [scope, currentRoot, currentTreeDepth, latestAspRoot] = await Promise.all([
    client.readContract({ address: POOL, abi: poolAbi, functionName: "SCOPE" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentRoot" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentTreeDepth" }),
    client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" }),
  ]);
  const scopePool = await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "scopeToPool", args: [scope] });
  assert(scopePool.toLowerCase() === POOL, "pool scope resolves to another pool");
  progress("contract-roots-validated");

  progress("fetching-asp-leaves");
  const response = await fetch(ASP_LEAVES, {
    headers: { "X-Pool-Scope": scope.toString() },
    signal: AbortSignal.timeout(120_000),
  });
  assert(response.ok, `ASP leaves request failed: HTTP ${response.status}`);
  const leaves = await response.json();
  const stateLeaves = leaves.stateTreeLeaves.map(BigInt);
  const aspLeaves = leaves.aspLeaves.map(BigInt);
  progress("asp-leaves-loaded", { stateLeaves: stateLeaves.length, aspLeaves: aspLeaves.length });
  const value = BigInt(note.value);
  const withdrawnValue = options.amount ? BigInt(options.amount) : value;
  assert(withdrawnValue > 0n && withdrawnValue <= value, "withdrawal amount is outside the note value");
  const label = BigInt(note.label);
  const nullifier = BigInt(note.nullifier);
  const secret = BigInt(note.secret);
  const commitment = getCommitment(value, label, nullifier, secret);
  assert(commitment.hash === BigInt(note.commitment), "private note does not reproduce commitment");
  const existingNullifierHash = BigInt(poseidon([nullifier]));
  const spent = await client.readContract({ address: POOL, abi: poolAbi, functionName: "nullifierHashes", args: [existingNullifierHash] });
  assert(spent === false, "note nullifier is already spent on-chain");

  const stateMerkleProof = generateMerkleProof(stateLeaves, commitment.hash);
  const aspMerkleProof = generateMerkleProof(aspLeaves, label);
  const stateTreeDepth = treeDepth(stateLeaves.length);
  const aspTreeDepth = treeDepth(aspLeaves.length);
  assert(stateMerkleProof.root === currentRoot, "ASP state leaves are stale versus pool currentRoot");
  assert(stateTreeDepth === currentTreeDepth, "state tree depth mismatch");
  assert(aspMerkleProof.root === latestAspRoot, "ASP approval leaves are stale versus Entrypoint.latestRoot");
  progress("merkle-proofs-validated");

  const withdrawal = { processooor, data: "0x" };
  const context = BigInt(calculateContext(withdrawal, scope));
  const newNullifier = fieldElement();
  let newSecret = fieldElement();
  while (newSecret === newNullifier) newSecret = fieldElement();
  const sdk = new PrivacyPoolSDK(new LocalWithdrawCircuits(artifacts));
  progress("proving");
  const withdrawalProof = await sdk.proveWithdrawal(commitment, {
    context,
    withdrawalAmount: withdrawnValue,
    stateMerkleProof,
    aspMerkleProof,
    stateRoot: currentRoot,
    stateTreeDepth,
    aspRoot: latestAspRoot,
    aspTreeDepth,
    newSecret,
    newNullifier,
  });
  progress("proof-generated");
  assert(await sdk.verifyWithdrawal(withdrawalProof), "local Groth16 verification failed");
  progress("proof-verified");
  const proof = formatProof(withdrawalProof);
  assert(proof.pubSignals.length === 8, "unexpected public signal count");
  assert(proof.pubSignals[1] === existingNullifierHash, "proof nullifier mismatch");
  assert(proof.pubSignals[2] === withdrawnValue, "proof value mismatch");
  assert(proof.pubSignals[3] === currentRoot, "proof state root mismatch");
  assert(proof.pubSignals[5] === latestAspRoot, "proof ASP root mismatch");
  assert(proof.pubSignals[7] === context, "proof context mismatch");
  const calldata = encodeFunctionData({ abi: poolAbi, functionName: "withdraw", args: [withdrawal, proof] });
  await client.call({ account: processooor, to: POOL, data: calldata });
  const estimatedGas = await client.estimateGas({ account: processooor, to: POOL, data: calldata });
  const finalAspRoot = await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" });
  assert(finalAspRoot === latestAspRoot, "ASP root changed during proving; run prepare again");
  progress("simulation-and-roots-validated", { estimatedGas });

  const remainingValue = value - withdrawnValue;
  const replacement = {
    parent_wallet: noteWallet,
    parent_id: id,
    replacement_id: replacementId,
    remaining_value: remainingValue.toString(),
    label: asHex(label),
    new_commitment: asHex(proof.pubSignals[0]),
    nullifier: asHex(newNullifier),
    secret: asHex(newSecret),
    calldata_hash: keccak256(calldata),
    backup_verified: true,
  };
  await verifiedBackup(replacement, replacementBackup, password, {
    kind: "replacement",
    wallet: noteWallet,
    id: replacementId,
    parent_id: id,
  });
  await atomicWrite(
    `${root}/secrets/privacy-pools/replacements/${noteWallet}/${replacementId}`,
    Buffer.from(`${JSON.stringify(replacement)}\n`),
    { exclusive: true },
  );
  const stageRequest = { signing_wallet: signingWallet, replacement_id: replacementId, calldata };
  await atomicWrite(output, Buffer.from(`${stringify(stageRequest)}\n`), { exclusive: true });
  progress("complete");
  console.log(stringify({
    proofVerified: true,
    simulationSucceeded: true,
    rootsFreshAfterProving: true,
    noteUnspent: true,
    processooor,
    withdrawalValueWei: withdrawnValue,
    remainingValueWei: remainingValue,
    estimatedGas,
    calldataBytes: (calldata.length - 2) / 2,
    stageRequest: output,
    replacementBackup,
  }));
}

async function persistJournal(path, journal) {
  await atomicWrite(path, Buffer.from(`${JSON.stringify(journal)}\n`));
}

function faultAfter(phase) {
  if (process.env.BLOOM_PP_FAULT_AFTER === phase) {
    process.kill(process.pid, "SIGKILL");
  }
}

export function withdrawnEvent(log, expected) {
  if (log.address.toLowerCase() !== POOL || log.topics[0]?.toLowerCase() !== WITHDRAWN_TOPIC.toLowerCase()) return false;
  if (!log.topics[1] || `0x${log.topics[1].slice(-40)}`.toLowerCase() !== ENTRYPOINT) return false;
  const words = log.data.slice(2).match(/.{64}/g)?.map((word) => BigInt(`0x${word}`)) ?? [];
  return words.length === 3
    && words[0] === expected.amount
    && words[1] === expected.nullifierHash
    && words[2] === expected.newCommitment;
}

async function recoverRelayTransaction(client, journal) {
  if (journal.start_block === undefined) return null;
  const logs = await client.getLogs({
    address: POOL,
    fromBlock: BigInt(journal.start_block),
    toBlock: "latest",
  });
  const expected = {
    amount: BigInt(journal.amount_wei),
    nullifierHash: BigInt(journal.existing_nullifier_hash),
    newCommitment: BigInt(journal.new_commitment),
  };
  return logs.find((log) => withdrawnEvent(log, expected))?.transactionHash ?? null;
}

async function waitUntilFinalized(client, receipt, timeoutMs = 20 * 60 * 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const finalized = await client.getBlock({ blockTag: "finalized" });
    if (finalized.number >= receipt.blockNumber) return finalized.number;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 12_000));
  }
  fail("settlement was mined but did not finalize before the local timeout; rerun to resume verification");
}

export function verifySettlementReceipt(receipt, journal) {
  assert(receipt.status === "success", "relayed withdrawal transaction reverted");
  const expected = {
    amount: BigInt(journal.amount_wei),
    nullifierHash: BigInt(journal.existing_nullifier_hash),
    newCommitment: BigInt(journal.new_commitment),
  };
  assert(receipt.logs.some((log) => withdrawnEvent(log, expected)), "receipt has no matching Privacy Pool Withdrawn event");

  const relayEvent = receipt.logs.find((log) =>
    log.address.toLowerCase() === ENTRYPOINT
    && log.topics[0]?.toLowerCase() === WITHDRAWAL_RELAYED_TOPIC.toLowerCase()
    && log.topics.length === 4,
  );
  assert(relayEvent, "receipt has no Entrypoint WithdrawalRelayed event");
  assert(`0x${relayEvent.topics[2].slice(-40)}`.toLowerCase() === journal.recipient.toLowerCase(), "WithdrawalRelayed recipient mismatch");
  assert(`0x${relayEvent.topics[3].slice(-40)}`.toLowerCase() === NATIVE_ASSET.toLowerCase(), "WithdrawalRelayed asset mismatch");
  const words = relayEvent.data.slice(2).match(/.{64}/g)?.map((word) => BigInt(`0x${word}`)) ?? [];
  assert(words.length === 2, "WithdrawalRelayed event data has the wrong shape");
  const expectedFee = expected.amount * BigInt(journal.fee_bps) / 10_000n;
  assert(words[0] === expected.amount && words[1] === expectedFee, "WithdrawalRelayed amount or fee mismatch");
}

export function completePrivateRelayStatus(publicStatus, remainingValue) {
  publicStatus.status = "complete";
  scrubLegacyPrivateRelayStatus(publicStatus);
  publicStatus.next = remainingValue > 0n
    ? "Settlement finalized. The backed-up replacement note is active."
    : "Settlement finalized. The original note is fully spent.";
  return publicStatus;
}

function scrubLegacyPrivateRelayStatus(publicStatus) {
  for (const field of ["approval_wallet", "ceremony_url", "ceremony_operation_id", "ceremony_expires_ms"]) {
    delete publicStatus[field];
  }
  return publicStatus;
}

async function finalizePrivateRelay({ client, journal, journalPath, note, notePath, root, statusPath, resultPath }) {
  journal.phase = "finalizing";
  await persistJournal(journalPath, journal);
  faultAfter("finalizing");
  const receipt = await client.waitForTransactionReceipt({ hash: journal.tx_hash, confirmations: 1, timeout: 180_000 });
  verifySettlementReceipt(receipt, journal);
  const finalizedBlock = await waitUntilFinalized(client, receipt);
  const canonicalBlock = await client.getBlock({ blockNumber: receipt.blockNumber });
  assert(canonicalBlock.hash === receipt.blockHash, "the relayed receipt was reorged before finality");
  assert(await client.readContract({
    address: POOL,
    abi: poolAbi,
    functionName: "nullifierHashes",
    args: [BigInt(journal.existing_nullifier_hash)],
    blockNumber: finalizedBlock,
  }) === true, "finalized pool state does not report the nullifier as spent");

  const result = {
    schema: "bloom.privacy-pools.private-relay-result.v1",
    request_id: journal.request_id,
    tx_hash: journal.tx_hash,
    relay_binding: journal.relay_binding,
  };
  const existingResult = await readJsonIfExists(resultPath);
  if (existingResult !== null) {
    assert(existingResult.tx_hash?.toLowerCase() === journal.tx_hash.toLowerCase(), "a different private relay result already exists");
  } else {
    await atomicWrite(resultPath, Buffer.from(`${JSON.stringify(result)}\n`), { exclusive: true });
  }

  note.spent = true;
  await atomicWrite(notePath, Buffer.from(`${JSON.stringify(note)}\n`));
  const depositStatusPath = `${root}/state/privacy-pools/deposits/${journal.note_wallet}/${journal.note_id}`;
  const depositStatus = JSON.parse(await readFile(depositStatusPath, "utf8"));
  depositStatus.spent = true;
  await atomicWrite(depositStatusPath, Buffer.from(`${JSON.stringify(depositStatus)}\n`), { mode: 0o644 });

  const remainingValue = BigInt(journal.remaining_value_wei);
  if (remainingValue > 0n) {
    const replacementNote = {
      wallet: journal.note_wallet,
      asset: note.asset,
      amount_wei: remainingValue.toString(),
      nullifier: journal.replacement.nullifier,
      secret: journal.replacement.secret,
      precommitment: asHex(BigInt(poseidon([
        BigInt(journal.replacement.nullifier),
        BigInt(journal.replacement.secret),
      ]))),
      status: "confirmed",
      tx: { chain: "mainnet", outbox_id: "private-relay" },
      value: remainingValue.toString(),
      label: journal.replacement.label,
      commitment: journal.new_commitment,
      spent: false,
      backup_verified: true,
    };
    await writeIdenticalOrCreate(
      `${root}/secrets/privacy-pools/notes/${journal.note_wallet}/${journal.replacement_id}`,
      replacementNote,
    );
    await writeIdenticalOrCreate(
      `${root}/state/privacy-pools/deposits/${journal.note_wallet}/${journal.replacement_id}`,
      redactPrivateReplacementNote(replacementNote),
      { mode: 0o644 },
    );
  }

  const publicStatus = completePrivateRelayStatus(
    JSON.parse(await readFile(statusPath, "utf8")),
    remainingValue,
  );
  await atomicWrite(statusPath, Buffer.from(`${JSON.stringify(publicStatus)}\n`), { mode: 0o644 });
  journal.phase = "complete";
  journal.finalized_block = finalizedBlock.toString();
  await persistJournal(journalPath, journal);
  privateProgress("complete");
  console.log(stringify({
    complete: true,
    proofVerified: true,
    settlementFinalized: true,
    nullifierSpent: true,
    replacementActive: remainingValue > 0n,
  }));
}

async function relayPrivateCommand(options) {
  privateProgress("starting");
  const noteWallet = safeSegment(required(options, "note-wallet"), "note wallet");
  const id = safeSegment(required(options, "id"), "id");
  const relayer = new URL(required(options, "relayer"));
  assert(!relayer.username && !relayer.password, "relayer URL must not contain credentials");
  assert(
    relayer.protocol === "https:" || (relayer.protocol === "http:" && ["localhost", "127.0.0.1"].includes(relayer.hostname)),
    "relayer must use HTTPS (HTTP is allowed only on loopback)",
  );
  const maxFeeText = required(options, "max-fee-bps");
  assert(/^\d+$/.test(maxFeeText), "max-fee-bps must be a non-negative integer");
  const maxFeeBPS = BigInt(maxFeeText);
  assert(maxFeeBPS <= 10_000n, "max-fee-bps cannot exceed 10000");
  const replacementBackup = resolve(required(options, "replacement-backup"));
  const password = await passphrase(resolve(required(options, "passphrase-file")));
  const artifacts = resolve(required(options, "artifacts"));
  const root = await activeDataRoot(bloomHome(options));
  const notePath = `${root}/secrets/privacy-pools/notes/${noteWallet}/${id}`;
  const statusPath = `${root}/state/privacy-pools/private-relays/${noteWallet}/${id}`;
  const note = JSON.parse(await readFile(notePath, "utf8"));
  const publicStatus = scrubLegacyPrivateRelayStatus(JSON.parse(await readFile(statusPath, "utf8")));
  assert(
    publicStatus.note_wallet === noteWallet && publicStatus.note_id === id,
    "private relay status belongs to another note",
  );
  const replacementId = safeSegment(publicStatus.replacement_id, "private relay replacement id");
  assert(id !== replacementId, "replacement id must differ from the existing note id");
  const resultPath = `${root}/secrets/privacy-pools/private-relay-results/${noteWallet}/${id}`;
  const journalPath = `${root}/secrets/privacy-pools/private-relay-attempts/${noteWallet}/${id}`;
  const replacementPath = `${root}/secrets/privacy-pools/replacements/${noteWallet}/${replacementId}`;
  const legacyRecipientPath = `${root}/secrets/privacy-pools/private-inputs/${noteWallet}/${id}`;
  assert(note.backup_verified === true, "existing note has no verified encrypted backup");
  for (const field of ["value", "label", "commitment"]) assert(note[field], `deposit is missing reconciled ${field}`);
  let journal = await readJsonIfExists(journalPath);

  if (journal?.phase === "complete") {
    privateProgress("complete");
    console.log(stringify({ complete: true, settlementFinalized: true, replacementActive: BigInt(journal.remaining_value_wei) > 0n }));
    return;
  }

  if (journal === null) {
    const value = BigInt(note.value);
    const withdrawnValue = publicStatus.amount_wei ? BigInt(publicStatus.amount_wei) : value;
    assert(withdrawnValue > 0n && withdrawnValue <= value, "withdrawal amount is outside the note value");
    const recipient = await collectPrivateRecipient({
      amountWei: withdrawnValue.toString(),
      source: `${noteWallet}/${id}`,
      relayer: relayer.origin,
      maxFeeBps: maxFeeBPS.toString(),
    });
    const newNullifier = fieldElement();
    let newSecret = fieldElement();
    while (newSecret === newNullifier) newSecret = fieldElement();
    const replacement = {
      parent_wallet: noteWallet,
      parent_id: id,
      replacement_id: replacementId,
      remaining_value: (value - withdrawnValue).toString(),
      label: asHex(BigInt(note.label)),
      nullifier: asHex(newNullifier),
      secret: asHex(newSecret),
      backup_verified: true,
    };
    journal = {
      schema: "bloom.privacy-pools.private-relay-attempt.v1",
      phase: "destination-ready",
      note_wallet: noteWallet,
      note_id: id,
      replacement_id: replacementId,
      recipient,
      amount_wei: withdrawnValue.toString(),
      remaining_value_wei: (value - withdrawnValue).toString(),
      replacement,
    };
    await persistJournal(journalPath, journal);
    publicStatus.status = "processing";
    publicStatus.next = "The local Privacy Pools helper accepted the destination and is processing the relay.";
    await atomicWrite(statusPath, Buffer.from(`${JSON.stringify(publicStatus)}\n`), { mode: 0o644 });
    faultAfter("destination-ready");
    await verifiedBackup(replacement, replacementBackup, password, {
      kind: "replacement",
      wallet: noteWallet,
      id: replacementId,
      parent_id: id,
    });
    await writeIdenticalOrCreate(replacementPath, replacement);
  } else {
    assert(journal.schema === "bloom.privacy-pools.private-relay-attempt.v1", "unsupported private relay journal");
    assert(
      journal.note_wallet === noteWallet && journal.note_id === id && journal.replacement_id === replacementId,
      "private relay journal belongs to another request",
    );
    assert(/^0x[0-9a-fA-F]{40}$/.test(journal.recipient), "private relay journal recipient is invalid");
    await verifiedBackup(journal.replacement, replacementBackup, password, {
      kind: "replacement",
      wallet: noteWallet,
      id: replacementId,
      parent_id: id,
    });
  }

  await unlink(legacyRecipientPath).catch((error) => {
    if (error?.code !== "ENOENT") throw error;
  });

  const rpcUrl = options.rpc ?? DEFAULT_RPC;
  const client = createPublicClient({ chain: mainnet, transport: http(rpcUrl) });
  const existingNullifierHash = BigInt(poseidon([BigInt(note.nullifier)]));

  if (["submitting", "ambiguous"].includes(journal.phase)) {
    const recovered = await recoverRelayTransaction(client, journal);
    if (recovered) {
      journal.tx_hash = recovered;
      journal.phase = "broadcast";
      await persistJournal(journalPath, journal);
    } else {
      const spent = await client.readContract({
        address: POOL,
        abi: poolAbi,
        functionName: "nullifierHashes",
        args: [existingNullifierHash],
      });
      assert(spent === false, "the note is spent but its matching withdrawal event was not recoverable from the journal start block");
      journal.phase = "ambiguous";
      await persistJournal(journalPath, journal);
      const oldEnough = Date.now() - Number(journal.submission_started_ms) >= AMBIGUOUS_RETRY_DELAY_MS;
      assert(options["retry-ambiguous"] === "yes" && oldEnough,
        "relay response was lost and no matching event is visible yet; wait five minutes, then rerun with --retry-ambiguous yes");
      journal.phase = "destination-ready";
      delete journal.start_block;
      delete journal.submission_started_ms;
      delete journal.tx_hash;
      await persistJournal(journalPath, journal);
    }
  }

  if (["broadcast", "finalizing"].includes(journal.phase)) {
    await finalizePrivateRelay({ client, journal, journalPath, note, notePath, root, statusPath, resultPath });
    return;
  }

  assert(note.spent !== true, "existing note is already marked spent");
  validateNoteSecrets(note);
  const value = BigInt(note.value);
  const withdrawnValue = BigInt(journal.amount_wei);
  const label = BigInt(note.label);
  const nullifier = BigInt(note.nullifier);
  const secret = BigInt(note.secret);
  const commitment = getCommitment(value, label, nullifier, secret);
  assert(commitment.hash === BigInt(note.commitment), "private note does not reproduce commitment");
  assert(await client.readContract({ address: POOL, abi: poolAbi, functionName: "nullifierHashes", args: [existingNullifierHash] }) === false,
    "note nullifier is already spent on-chain");

  const [scope, currentRoot, currentTreeDepth, latestAspRoot] = await Promise.all([
    client.readContract({ address: POOL, abi: poolAbi, functionName: "SCOPE" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentRoot" }),
    client.readContract({ address: POOL, abi: poolAbi, functionName: "currentTreeDepth" }),
    client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" }),
  ]);
  const scopePool = await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "scopeToPool", args: [scope] });
  assert(scopePool.toLowerCase() === POOL, "pool scope resolves to another pool");
  const circuits = new LocalWithdrawCircuits(artifacts);
  const detailsUrl = new URL("/relayer/details", relayer);
  detailsUrl.searchParams.set("chainId", "1");
  detailsUrl.searchParams.set("assetAddress", NATIVE_ASSET);
  const [leavesResponse, detailsResponse] = await Promise.all([
    fetch(ASP_LEAVES, { headers: { "X-Pool-Scope": scope.toString() }, signal: AbortSignal.timeout(120_000) })
      .catch(() => fail("ASP leaves request failed before an HTTP response")),
    fetch(detailsUrl, { signal: AbortSignal.timeout(30_000) })
      .catch(() => fail("relayer details failed before an HTTP response")),
    circuits.preload(),
  ]);
  assert(leavesResponse.ok, `ASP leaves request failed: HTTP ${leavesResponse.status}`);
  assert(detailsResponse.ok, `relayer details failed: HTTP ${detailsResponse.status}`);
  const detailsEnvelope = await detailsResponse.json();
  const details = detailsEnvelope.data ?? detailsEnvelope;
  assert(Number(details.chainId) === 1, "relayer details returned another chain");
  assert(details.assetAddress?.toLowerCase() === NATIVE_ASSET.toLowerCase(), "relayer details returned another asset");
  assert(BigInt(details.minWithdrawAmount ?? 0) <= withdrawnValue, "withdrawal is below relayer minimum");
  const leaves = await leavesResponse.json();
  const stateLeaves = leaves.stateTreeLeaves.map(BigInt);
  const aspLeaves = leaves.aspLeaves.map(BigInt);
  const stateMerkleProof = generateMerkleProof(stateLeaves, commitment.hash);
  const aspMerkleProof = generateMerkleProof(aspLeaves, label);
  const stateTreeDepth = treeDepth(stateLeaves.length);
  const aspTreeDepth = treeDepth(aspLeaves.length);
  assert(stateMerkleProof.root === currentRoot && stateTreeDepth === currentTreeDepth, "ASP state leaves are stale versus the pool");
  assert(aspMerkleProof.root === latestAspRoot, "ASP approval leaves are stale versus Entrypoint.latestRoot");

  const quoteResponse = await fetch(new URL("/relayer/quote", relayer), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chainId: 1, amount: withdrawnValue.toString(), asset: NATIVE_ASSET, recipient: journal.recipient }),
    signal: AbortSignal.timeout(60_000),
  });
  assert(quoteResponse.ok, `relayer quote failed: HTTP ${quoteResponse.status}`);
  const quote = await quoteResponse.json();
  const validatedQuote = validateRelayQuote(quote, {
    recipient: journal.recipient,
    amount: withdrawnValue,
    maxFeeBPS,
  });
  assert(Number(quote.feeCommitment.expiration) > Date.now() + QUOTE_SAFETY_MS, "relayer quote lifetime is too short for safe proving");
  const withdrawal = { processooor: ENTRYPOINT, data: validatedQuote.withdrawalData };
  const context = BigInt(calculateContext(withdrawal, scope));
  journal.phase = "proving";
  await persistJournal(journalPath, journal);
  faultAfter("proving");
  const sdk = new PrivacyPoolSDK(circuits);
  const withdrawalProof = await sdk.proveWithdrawal(commitment, {
    context,
    withdrawalAmount: withdrawnValue,
    stateMerkleProof,
    aspMerkleProof,
    stateRoot: currentRoot,
    stateTreeDepth,
    aspRoot: latestAspRoot,
    aspTreeDepth,
    newSecret: BigInt(journal.replacement.secret),
    newNullifier: BigInt(journal.replacement.nullifier),
  });
  assert(await sdk.verifyWithdrawal(withdrawalProof), "local Groth16 verification failed");
  const proof = formatProof(withdrawalProof);
  assert(proof.pubSignals[1] === existingNullifierHash, "proof nullifier mismatch");
  assert(proof.pubSignals[2] === withdrawnValue, "proof value mismatch");
  assert(proof.pubSignals[3] === currentRoot && proof.pubSignals[5] === latestAspRoot, "proof roots mismatch");
  assert(proof.pubSignals[7] === context, "proof context mismatch");
  assert(Number(quote.feeCommitment.expiration) > Date.now() + QUOTE_SAFETY_MS, "signed relayer quote expired during proving");
  const relayBinding = keccak256(toHex(JSON.stringify({
    withdrawal,
    publicSignals: withdrawalProof.publicSignals.map(String),
    scope: scope.toString(),
  })));
  journal.phase = "proof-ready";
  journal.existing_nullifier_hash = asHex(existingNullifierHash);
  journal.new_commitment = asHex(proof.pubSignals[0]);
  journal.fee_bps = validatedQuote.feeBPS.toString();
  journal.relay_binding = relayBinding;
  journal.withdrawal = withdrawal;
  journal.proof = withdrawalProof.proof;
  journal.public_signals = withdrawalProof.publicSignals.map(String);
  journal.fee_commitment = quote.feeCommitment;
  journal.scope = scope.toString();
  await persistJournal(journalPath, journal);
  faultAfter("proof-ready");
  await atomicWrite(
    replacementPath,
    Buffer.from(`${JSON.stringify({ ...journal.replacement, new_commitment: journal.new_commitment })}\n`),
  );

  await client.simulateContract({
    address: ENTRYPOINT,
    abi: entrypointAbi,
    functionName: "relay",
    args: [withdrawal, proof, scope],
    account: validatedQuote.feeRecipient,
  });
  await client.estimateContractGas({
    address: ENTRYPOINT,
    abi: entrypointAbi,
    functionName: "relay",
    args: [withdrawal, proof, scope],
    account: validatedQuote.feeRecipient,
  });
  assert(await client.readContract({ address: POOL, abi: poolAbi, functionName: "currentRoot" }) === currentRoot,
    "pool root changed after proving; rerun to create a fresh proof");
  assert(await client.readContract({ address: ENTRYPOINT, abi: entrypointAbi, functionName: "latestRoot" }) === latestAspRoot,
    "ASP root changed after proving; rerun to create a fresh proof");
  assert(Number(quote.feeCommitment.expiration) > Date.now() + 5_000, "signed relayer quote is too close to expiry for submission");

  const relayPayload = {
    chainId: 1,
    scope: scope.toString(),
    withdrawal,
    proof: withdrawalProof.proof,
    publicSignals: withdrawalProof.publicSignals.map(String),
    feeCommitment: quote.feeCommitment,
  };
  journal.phase = "submitting";
  journal.start_block = (await client.getBlockNumber()).toString();
  journal.submission_started_ms = Date.now();
  await persistJournal(journalPath, journal);
  faultAfter("submitting");
  let relayed;
  try {
    const relayResponse = await fetch(new URL("/relayer/request", relayer), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(relayPayload),
      signal: AbortSignal.timeout(120_000),
    });
    assert(relayResponse.ok, `relayer submission failed: HTTP ${relayResponse.status}`);
    relayed = await relayResponse.json();
    assert(relayed.success === true && /^0x[0-9a-fA-F]{64}$/.test(relayed.txHash ?? ""), "relayer did not return a successful transaction hash");
    journal.tx_hash = relayed.txHash;
    journal.request_id = relayed.requestId;
  } catch (error) {
    journal.phase = "ambiguous";
    await persistJournal(journalPath, journal);
    faultAfter("ambiguous");
    const recovered = await recoverRelayTransaction(client, journal);
    if (!recovered) throw error;
    journal.tx_hash = recovered;
  }
  journal.phase = "broadcast";
  await persistJournal(journalPath, journal);
  faultAfter("broadcast");
  await finalizePrivateRelay({ client, journal, journalPath, note, notePath, root, statusPath, resultPath });
}

function usage() {
  return `Usage:
  bloom-privacy-pools backup --wallet W --id ID --out FILE --passphrase-file FILE [--home DIR]
  bloom-privacy-pools restore --in FILE --passphrase-file FILE [--home DIR]
    (a v1/legacy-schema backup additionally requires --trust-legacy-wallet W --trust-legacy-id ID
     --trust-legacy-kind deposit|replacement, asserting out of band what its unauthenticated
     metadata is trusted to claim)
  bloom-privacy-pools verify-artifacts --artifacts DIR
  bloom-privacy-pools prepare --note-wallet W --id ID --signing-wallet W --replacement-id ID --artifacts DIR --replacement-backup FILE --passphrase-file FILE --out FILE [--amount WEI] [--rpc URL] [--home DIR]
  bloom-privacy-pools relay-private --note-wallet W --id ID --relayer URL --max-fee-bps BPS --artifacts DIR --replacement-backup FILE --passphrase-file FILE [--retry-ambiguous yes] [--rpc URL] [--home DIR]`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { command, options } = parseArgs(process.argv.slice(2));
  const commands = {
    backup: backupCommand,
    restore: restoreCommand,
    "verify-artifacts": verifyArtifactsCommand,
    prepare: prepareCommand,
    "relay-private": relayPrivateCommand,
  };
  if (!commands[command]) {
    console.error(usage());
    process.exitCode = 2;
  } else {
    commands[command](options).catch((error) => {
      if (command === "relay-private") {
        // Library and provider errors can include witness inputs or request
        // payloads. Never project an arbitrary nested error into an
        // agent-visible terminal for the recipient-private workflow.
        console.error(stringify({
          petal: "privacy-pools",
          command,
          phase: "failed",
          error: "private relay failed; retry or inspect it locally outside the agent session",
        }));
      } else {
        console.error(`privacy-pools ${command} failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      process.exitCode = 1;
    });
  }
}
