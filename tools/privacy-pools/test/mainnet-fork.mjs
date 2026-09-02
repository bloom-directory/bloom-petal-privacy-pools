import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient,
  createWalletClient,
  encodeAbiParameters,
  http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mainnet } from "viem/chains";

const ENTRYPOINT = "0x6818809eefce719e480a7526d76bd3e561526b46";
const NATIVE_ASSET = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
const RECIPIENT = "0x1111111111111111111111111111111111111111";
const ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const entrypointAbi = [{
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
}];

function option(name) {
  const index = process.argv.indexOf(`--${name}`);
  assert(index >= 0 && process.argv[index + 1], `missing --${name}`);
  return resolve(process.argv[index + 1]);
}

function solidityProof(body) {
  return {
    pA: [BigInt(body.proof.pi_a[0]), BigInt(body.proof.pi_a[1])],
    pB: [
      [BigInt(body.proof.pi_b[0][1]), BigInt(body.proof.pi_b[0][0])],
      [BigInt(body.proof.pi_b[1][1]), BigInt(body.proof.pi_b[1][0])],
    ],
    pC: [BigInt(body.proof.pi_c[0]), BigInt(body.proof.pi_c[1])],
    pubSignals: body.publicSignals.map(BigInt),
  };
}

async function jsonBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function waitForRpc(client) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await client.getBlockNumber();
      return;
    } catch {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
    }
  }
  throw new Error("anvil fork did not start");
}

async function runCli(args, env) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("privacy-pools fork helper timed out"));
    }, 180_000);
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      clearTimeout(timeout);
      resolvePromise({ status: code, signal, stdout, stderr });
    });
  });
}

const noteSource = option("note");
const depositStatusSource = option("deposit-status");
const artifacts = option("artifacts");
const forkUrl = process.env.ETH_RPC_URL ?? "https://ethereum-rpc.publicnode.com";
const port = 18_545 + Math.floor(Math.random() * 1_000);
const rpcUrl = `http://127.0.0.1:${port}`;
const anvil = spawn(process.env.ANVIL ?? "anvil", [
  "--fork-url", forkUrl,
  "--chain-id", "1",
  "--port", String(port),
  "--silent",
], { stdio: "ignore" });

const account = privateKeyToAccount(ANVIL_KEY);
const publicClient = createPublicClient({ chain: mainnet, transport: http(rpcUrl) });
const walletClient = createWalletClient({ account, chain: mainnet, transport: http(rpcUrl) });
let server;
let testHome;
try {
  await waitForRpc(publicClient);
  server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://127.0.0.1");
      if (request.method === "GET" && url.pathname === "/relayer/details") {
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify({
          feeBPS: 0,
          feeReceiverAddress: account.address,
          chainId: 1,
          maxGasPrice: "1000000000000",
          assetAddress: NATIVE_ASSET,
          minWithdrawAmount: "0",
        }));
        return;
      }
      if (request.method === "POST" && url.pathname === "/relayer/quote") {
        const body = await jsonBody(request);
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify({
          feeBPS: "0",
          feeCommitment: {
            expiration: Date.now() + 120_000,
            withdrawalData: encodeAbiParameters(
              [{ type: "address" }, { type: "address" }, { type: "uint256" }],
              [body.recipient, account.address, 0n],
            ),
            signedRelayerCommitment: "0x01",
            asset: NATIVE_ASSET,
            amount: body.amount,
            extraGas: false,
          },
        }));
        return;
      }
      if (request.method === "POST" && url.pathname === "/relayer/request") {
        const body = await jsonBody(request);
        const hash = await walletClient.writeContract({
          address: ENTRYPOINT,
          abi: entrypointAbi,
          functionName: "relay",
          args: [body.withdrawal, solidityProof(body), BigInt(body.scope)],
        });
        await publicClient.waitForTransactionReceipt({ hash });
        await publicClient.request({ method: "anvil_mine", params: ["0x40"] });
        response.socket.destroy();
        return;
      }
      response.statusCode = 404;
      response.end();
    } catch {
      if (!response.destroyed) {
        response.statusCode = 500;
        response.end();
      }
    }
  });
  await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  const relayerUrl = `http://127.0.0.1:${server.address().port}`;

  testHome = await mkdtemp(join(tmpdir(), "privacy-pools-fork-"));
  const hash = "f".repeat(64);
  const dataRoot = join(testHome, "petals", "data", hash);
  const notePath = join(dataRoot, "secrets/privacy-pools/notes/dev/pp-deposit-1");
  const depositStatusPath = join(dataRoot, "state/privacy-pools/deposits/dev/pp-deposit-1");
  const relayStatusPath = join(dataRoot, "state/privacy-pools/private-relays/dev/pp-deposit-1");
  for (const path of [notePath, depositStatusPath, relayStatusPath]) await mkdir(dirname(path), { recursive: true });
  await mkdir(join(testHome, "petals/store/owners"), { recursive: true });
  await writeFile(join(testHome, "petals/store/owners/privacy-pools.json"), JSON.stringify({ hash }));
  await cp(noteSource, notePath);
  await cp(depositStatusSource, depositStatusPath);
  const copiedNote = JSON.parse(await readFile(notePath, "utf8"));
  copiedNote.backup_verified = true;
  copiedNote.spent = false;
  await writeFile(notePath, JSON.stringify(copiedNote));
  await writeFile(relayStatusPath, JSON.stringify({
    note_wallet: "dev",
    note_id: "pp-deposit-1",
    replacement_id: "fork-replacement",
    status: "awaiting-owner-input",
    next: "fork test",
  }));
  const browserBin = join(testHome, "bin");
  const browserOpener = join(browserBin, "xdg-open");
  await mkdir(browserBin, { recursive: true });
  await writeFile(browserOpener, `#!/usr/bin/env node
const url = new URL(process.argv[2]);
const token = url.pathname.split("/").pop();
fetch(new URL("/submit", url), {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Origin": url.origin,
    "X-Private-Input-Token": token,
  },
  body: JSON.stringify({ recipient: "${RECIPIENT}" }),
}).then((response) => {
  if (!response.ok) process.exitCode = 1;
});
`);
  await chmod(browserOpener, 0o755);
  const passphrase = join(testHome, "passphrase");
  await writeFile(passphrase, "fork testing passphrase\n", { mode: 0o600 });
  await chmod(passphrase, 0o600);
  const cli = fileURLToPath(new URL("../cli.mjs", import.meta.url));
  const args = [
    cli, "relay-private",
    "--note-wallet", "dev",
    "--id", "pp-deposit-1",
    "--relayer", relayerUrl,
    "--max-fee-bps", "0",
    "--artifacts", artifacts,
    "--replacement-backup", join(testHome, "replacement.enc.json"),
    "--passphrase-file", passphrase,
    "--rpc", rpcUrl,
    "--home", testHome,
  ];
  const first = await runCli(args, {
    ...process.env,
    PATH: `${browserBin}:${process.env.PATH}`,
    BLOOM_PP_FAULT_AFTER: "ambiguous",
  });
  assert.equal(first.signal, "SIGKILL", `expected injected crash; stderr=${first.stderr}`);
  const second = await runCli(args, { ...process.env, PATH: `${browserBin}:${process.env.PATH}` });
  assert.equal(second.status, 0, `resume failed; stderr=${second.stderr}`);
  assert.match(second.stdout, /"settlementFinalized": true/);
  assert.doesNotMatch(`${first.stdout}${first.stderr}${second.stdout}${second.stderr}`, new RegExp(RECIPIENT, "i"));
  const journal = JSON.parse(await readFile(join(dataRoot, "secrets/privacy-pools/private-relay-attempts/dev/pp-deposit-1"), "utf8"));
  assert.equal(journal.phase, "complete");
  console.log(JSON.stringify({ forkWithdrawal: "complete", lostResponseRecovered: true, recipientRedacted: true }));
} finally {
  await new Promise((resolvePromise) => server?.close(resolvePromise) ?? resolvePromise());
  anvil.kill("SIGTERM");
  if (testHome) await rm(testHome, { recursive: true });
}
