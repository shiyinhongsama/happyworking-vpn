import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { artifacts, openApp, tauriMock, waitFor } from "./harness.mjs";

const mock = tauriMock({
  setup: "let loginAttempt = 0;",
  commands: `
    if (command === "probe_gateway") return Promise.resolve({
      fingerprint: "AA:BB", subject: "测试网关", commonName: "gateway.test"
    });
    if (command === "trust_and_discover") return Promise.resolve({
      stage: "ready", message: "网关能力发现完成，可以登录"
    });
    if (command === "load_saved_credential") return Promise.resolve({ password: null });
    if (command === "login_gateway") {
      loginAttempt += 1;
      if (loginAttempt === 1) return Promise.reject({ message: "模拟：账号或密码错误" });
      return new Promise((resolve) => {
        window.finishTestLogin = () => resolve({
          stage: "authenticated", message: "认证成功；隧道尚未建立"
        });
      });
    }
  `,
});

test("登录步骤和结果在当前窗口清晰可见", async (t) => {
  const devtools = await openApp(t, { mock, port: 1421 });

  const initialDisplay = await devtools.evaluate(`Object.fromEntries(
    ["login-form", "challenge-form", "authenticated-section", "connected-section"]
      .map((id) => [id, getComputedStyle(document.getElementById(id)).display])
  )`);
  assert.equal(initialDisplay["login-form"], "none", "证书确认前不应显示登录表单");
  assert.equal(initialDisplay["challenge-form"], "none");
  assert.equal(initialDisplay["authenticated-section"], "none");
  assert.equal(await devtools.evaluate('document.getElementById("gateway-host").value'), "122.224.205.114");
  assert.equal(await devtools.evaluate('document.getElementById("gateway-port").value'), "4435");
  assert.equal(
    await devtools.evaluate('document.querySelector("[data-step=gateway]").classList.contains("is-active")'),
    true,
    "初始状态应突出网关步骤",
  );
  if (process.env.UI_SCREENSHOT) {
    const screenshot = await devtools.send("Page.captureScreenshot", { format: "png" });
    const file = path.join(
      artifacts,
      path.basename(process.env.UI_SCREENSHOT, ".png") + "-initial.png",
    );
    await writeFile(file, Buffer.from(screenshot.data, "base64"));
  }

  await devtools.evaluate(`document.getElementById("gateway-host").value = "gateway.test";
    document.getElementById("config-form").requestSubmit();`);
  await waitFor(() => devtools.evaluate('!document.getElementById("certificate-section").hidden'), "证书确认");
  assert.equal(await devtools.evaluate('document.getElementById("config-form").hidden'), true);
  await devtools.evaluate('document.getElementById("trust-button").click()');
  await waitFor(() => devtools.evaluate('!document.getElementById("login-form").hidden'), "登录表单");
  assert.equal(
    await devtools.evaluate('document.querySelector("[data-step=identity]").classList.contains("is-active")'),
    true,
  );

  await devtools.evaluate(`document.getElementById("username").value = "test-user";
    document.getElementById("password").value = "test-password";
    document.getElementById("login-form").requestSubmit();`);
  await waitFor(() => devtools.evaluate('!document.getElementById("error-message").hidden'), "失败提示");
  const failure = await devtools.evaluate(`(() => {
    const error = document.getElementById("error-message");
    const rect = error.getBoundingClientRect();
    return {
      message: error.textContent,
      status: document.getElementById("status-message").textContent,
      visible: rect.top >= 0 && rect.bottom <= innerHeight,
      password: document.getElementById("password").value,
    };
  })()`);
  assert.match(failure.message, /账号或密码错误/);
  assert.equal(failure.status, "操作未完成");
  assert.equal(failure.password, "", "失败后应清空密码");
  assert.ok(failure.visible, "失败原因应位于可视区域内");

  await devtools.evaluate(`document.getElementById("password").value = "test-password";
    document.getElementById("login-form").requestSubmit();`);
  const pending = await devtools.evaluate(`({
    status: document.getElementById("status-message").textContent,
    disabled: document.getElementById("login-button").disabled,
  })`);
  assert.match(pending.status, /正在提交凭据/);
  assert.ok(pending.disabled, "登录期间应防止重复提交");
  await devtools.evaluate("window.finishTestLogin()");
  await waitFor(() => devtools.evaluate('!document.getElementById("authenticated-section").hidden'), "认证结果");
  const result = await devtools.evaluate(`(() => {
    const status = document.getElementById("status-message");
    const success = document.getElementById("authenticated-section");
    const statusRect = status.getBoundingClientRect();
    const successRect = success.getBoundingClientRect();
    return {
      loginDisplay: getComputedStyle(document.getElementById("login-form")).display,
      successDisplay: getComputedStyle(success).display,
      state: document.getElementById("state-text").textContent,
      status: status.textContent,
      statusVisible: statusRect.top >= 0 && statusRect.bottom <= innerHeight,
      successVisible: successRect.top >= 0 && successRect.bottom <= innerHeight,
    };
  })()`);
  assert.equal(result.loginDisplay, "none", "认证成功后应收起登录表单");
  assert.notEqual(result.successDisplay, "none");
  assert.equal(result.state, "认证成功");
  assert.match(result.status, /认证成功/);
  assert.ok(result.statusVisible, "认证结果提示应位于可视区域内");
  assert.ok(result.successVisible, "建立隧道操作应位于可视区域内");

  await devtools.evaluate(`window.emitTestEvent("vpn-state", "connected");
    window.emitTestEvent("vpn-stage", "connected");
    window.emitTestEvent("tunnel-ready", { interface: "omvpn-test", address: "192.0.2.2" });`);
  await waitFor(() => devtools.evaluate('document.getElementById("status-message").textContent === "隧道已连接，可以访问公司内网"'), "隧道成功提示");
  assert.equal(await devtools.evaluate('document.getElementById("connected-section").hidden'), false);
  assert.equal(
    await devtools.evaluate('document.querySelector("[data-step=tunnel]").classList.contains("is-active")'),
    true,
  );
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(await devtools.evaluate('document.documentElement.scrollWidth <= innerWidth'), true);

  if (process.env.UI_SCREENSHOT) {
    const screenshot = await devtools.send("Page.captureScreenshot", { format: "png" });
    const file = path.join(
      artifacts,
      path.basename(process.env.UI_SCREENSHOT, ".png") + "-connected.png",
    );
    await writeFile(file, Buffer.from(screenshot.data, "base64"));
  }

  await devtools.send("Emulation.setDeviceMetricsOverride", {
    width: 360,
    height: 740,
    deviceScaleFactor: 1,
    mobile: false,
  });
  assert.equal(await devtools.evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
  if (process.env.UI_SCREENSHOT) {
    const screenshot = await devtools.send("Page.captureScreenshot", { format: "png" });
    const file = path.join(
      artifacts,
      path.basename(process.env.UI_SCREENSHOT, ".png") + "-mobile.png",
    );
    await writeFile(file, Buffer.from(screenshot.data, "base64"));
  }
});
