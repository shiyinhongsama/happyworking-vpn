import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { artifacts, openApp, tauriMock, waitFor } from "./harness.mjs";

const mock = tauriMock({
  setup: "window.startTunnelCalls = 0;",
  commands: `
    if (command === "start_tunnel") {
      window.startTunnelCalls += 1;
      return Promise.resolve({ stage: "tunnel-starting", message: "正在请求权限并建立隧道" });
    }
  `,
});

test("隧道断开后界面立刻给出可见反馈，并能一键重连", async (t) => {
  const devtools = await openApp(t, { mock, port: 1422 });

  await devtools.evaluate(`window.emitTestEvent("vpn-state", "connected");
    window.emitTestEvent("vpn-stage", "connected");
    window.emitTestEvent("tunnel-ready", { interface: "omvpn-test", address: "192.0.2.2" });`);
  await waitFor(
    () => devtools.evaluate('document.getElementById("state-text").textContent === "已连接"'),
    "隧道已连接",
  );
  assert.equal(
    await devtools.evaluate('document.getElementById("disconnect-banner").hidden'),
    true,
    "连接正常时不应显示断线横幅",
  );

  await devtools.evaluate(`window.emitTestEvent("vpn-state", "reconnecting");
    window.emitTestEvent("vpn-stage", "tunnel-lost");
    window.emitTestEvent("tunnel-lost", {
      reason: "隧道已中断：网关关闭了连接",
      attempt: 1,
      willRetry: true,
    });`);
  await waitFor(
    () => devtools.evaluate('document.getElementById("state-text").textContent === "正在重连"'),
    "重连状态",
  );

  const reconnecting = await devtools.evaluate(`(() => {
    const banner = document.getElementById("disconnect-banner");
    const rect = banner.getBoundingClientRect();
    return {
      badge: document.getElementById("state-text").textContent,
      badgeState: document.getElementById("state-badge").dataset.state,
      hidden: banner.hidden,
      visible: rect.top >= 0 && rect.bottom <= innerHeight,
      title: document.getElementById("disconnect-title").textContent,
      detail: document.getElementById("disconnect-detail").textContent,
      connectedHidden: document.getElementById("connected-section").hidden,
    };
  })()`);
  assert.equal(reconnecting.badge, "正在重连", "断线后徽标必须说明正在重连");
  assert.equal(reconnecting.badgeState, "reconnecting");
  assert.notEqual(reconnecting.badgeState, "connected", "断线后不能还显示已连接");
  assert.equal(reconnecting.hidden, false, "断线横幅必须出现");
  assert.ok(reconnecting.visible, "断线横幅应位于可视区域内");
  assert.match(reconnecting.title, /正在自动重连/);
  assert.match(reconnecting.detail, /网关关闭了连接/, "横幅要说明断开原因");
  assert.equal(reconnecting.connectedHidden, true, "断线后不应继续展示已连接的面板");

  await devtools.evaluate(`window.emitTestEvent("vpn-state", "failed");
    window.emitTestEvent("vpn-stage", "tunnel-lost");
    window.emitTestEvent("tunnel-lost", {
      reason: "隧道建立失败：会话已过期",
      attempt: 5,
      willRetry: false,
    });`);
  await waitFor(
    () => devtools.evaluate('document.getElementById("state-text").textContent === "连接失败"'),
    "重连失败状态",
  );
  const failed = await devtools.evaluate(`({
    title: document.getElementById("disconnect-title").textContent,
    detail: document.getElementById("disconnect-detail").textContent,
  })`);
  assert.match(failed.title, /自动重连失败/);
  assert.match(failed.detail, /重新登录/, "重连失败要提示可以重新登录");

  await devtools.evaluate('document.getElementById("reconnect-button").click()');
  await waitFor(() => devtools.evaluate("window.startTunnelCalls === 1"), "手动重连");
  assert.equal(
    await devtools.evaluate("window.startTunnelCalls"),
    1,
    "点击立即重连应重新发起隧道",
  );

  if (process.env.UI_SCREENSHOT) {
    const screenshot = await devtools.send("Page.captureScreenshot", { format: "png" });
    const file = path.join(
      artifacts,
      path.basename(process.env.UI_SCREENSHOT, ".png") + "-disconnect.png",
    );
    await writeFile(file, Buffer.from(screenshot.data, "base64"));
  }
});
