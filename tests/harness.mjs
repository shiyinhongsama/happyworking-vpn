import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const artifacts = path.join(project, ".analysis");

export async function waitFor(check, description) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      if (await check()) return;
    } catch {
      // 浏览器或服务可能还没准备好。
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`等待超时：${description}`);
}

export class DevTools {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.socket.addEventListener("message", ({ data }) => {
      const message = JSON.parse(data);
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
    });
  }

  async open() {
    await new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", reject, { once: true });
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.text);
    }
    return result.result.value;
  }

  close() {
    this.socket.close();
  }
}

/**
 * 造一个 Tauri 模拟层：invoke 走 `commands` 里的分支，事件用 emitTestEvent 派发。
 */
export function tauriMock({ setup = "", commands = "" } = {}) {
  return `
    let callbackId = 0;
    const callbacks = new Map();
    const callbackEvents = new Map();
    ${setup}
    window.__TAURI_INTERNALS__ = {
      transformCallback(callback) {
        const id = ++callbackId;
        callbacks.set(id, callback);
        return id;
      },
      unregisterCallback(id) { callbacks.delete(id); callbackEvents.delete(id); },
      invoke(command, args) {
        if (command === "plugin:event|listen") {
          callbackEvents.set(args.handler, args.event);
          return Promise.resolve(++callbackId);
        }
        if (command === "plugin:event|unlisten") return Promise.resolve(null);
        if (command === "get_core_state") return Promise.resolve("disconnected");
        ${commands}
        return Promise.reject(new Error("未模拟的命令：" + command));
      }
    };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener() {} };
    window.emitTestEvent = (event, payload) => {
      for (const [id, callback] of callbacks) {
        if (callbackEvents.get(id) === event) callback({ event, payload });
      }
    };
  `;
}

/**
 * 拉起前端与无头浏览器，注入模拟层并等到应用初始化完成。
 */
export async function openApp(t, { mock, port }) {
  await mkdir(artifacts, { recursive: true });
  const profile = await mkdtemp(path.join(artifacts, "ui-test-"));
  const server = spawn(
    process.execPath,
    [
      path.join(project, "node_modules/vite/bin/vite.js"),
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--strictPort",
    ],
    { cwd: project, stdio: "ignore" },
  );
  let browser;
  let devtools;

  t.after(async () => {
    devtools?.close();
    const waitForExit = (child) =>
      child && child.exitCode === null && child.signalCode === null
        ? new Promise((resolve) => child.once("exit", resolve))
        : Promise.resolve();
    const browserExited = waitForExit(browser);
    const serverExited = waitForExit(server);
    browser?.kill("SIGTERM");
    server.kill("SIGTERM");
    await Promise.all([browserExited, serverExited]);
    await rm(profile, { recursive: true, force: true });
  });

  await waitFor(async () => (await fetch(`http://127.0.0.1:${port}`)).ok, "Vite");
  browser = spawn(
    "chromium",
    [
      "--headless",
      "--no-sandbox",
      "--disable-gpu",
      "--no-first-run",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "--window-size=920,640",
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  let debuggingPort;
  await waitFor(async () => {
    debuggingPort = (await readFile(path.join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0];
    return Boolean(debuggingPort);
  }, "Chromium DevTools");
  const targets = await (await fetch(`http://127.0.0.1:${debuggingPort}/json/list`)).json();
  devtools = new DevTools(targets.find((target) => target.type === "page").webSocketDebuggerUrl);
  await devtools.open();
  await devtools.send("Page.enable");
  await devtools.send("Runtime.enable");
  await devtools.send("Emulation.setDeviceMetricsOverride", {
    width: 920,
    height: 640,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await devtools.send("Page.addScriptToEvaluateOnNewDocument", { source: mock });
  await devtools.send("Page.navigate", { url: `http://127.0.0.1:${port}` });
  await waitFor(
    () =>
      devtools.evaluate(
        'document.readyState === "complete" && document.querySelector("#state-text").textContent === "未连接"',
      ),
    "应用初始化",
  );
  return devtools;
}
