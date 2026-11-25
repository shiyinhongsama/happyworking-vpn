import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type ConnectionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "reconnecting"
  | "failed";

type CertificateView = {
  fingerprint: string;
  subject: string;
  commonName: string | null;
};

type AuthView = {
  stage: string;
  message: string;
};

type TunnelLost = {
  reason: string;
  attempt: number;
  willRetry: boolean;
};

type VpnError = {
  code: string;
  message: string;
};

const stateText: Record<ConnectionState, string> = {
  disconnected: "未连接",
  connecting: "正在连接",
  connected: "已连接",
  disconnecting: "正在断开",
  reconnecting: "正在重连",
  failed: "连接失败",
};

const stageText: Record<string, string> = {
  certificate: "待确认证书",
  ready: "待登录",
  challenge: "需要二次认证",
  authenticated: "认证成功",
  "tunnel-starting": "正在建立隧道",
  connected: "已连接",
  "tunnel-lost": "连接已断开",
  disconnected: "未连接",
};

const stageElements: Record<string, string> = {
  certificate: "certificate-section",
  ready: "login-form",
  challenge: "challenge-form",
  authenticated: "authenticated-section",
  "tunnel-starting": "authenticated-section",
  connected: "connected-section",
};

const stageCopy: Record<string, {
  kicker: string;
  title: string;
  description: string;
  step: number;
}> = {
  disconnected: {
    kicker: "01 / GATEWAY",
    title: "连接公司网关",
    description: "确认接入点与安全策略，建立一条可信的私有链路。",
    step: 0,
  },
  certificate: {
    kicker: "01 / CERTIFICATE",
    title: "确认网关身份",
    description: "证书是链路的身份证明，请先核对，再继续。",
    step: 0,
  },
  ready: {
    kicker: "02 / IDENTITY",
    title: "验证你的身份",
    description: "使用公司账号完成认证，凭据不会写入本地文件。",
    step: 1,
  },
  challenge: {
    kicker: "02 / SECOND FACTOR",
    title: "完成二次认证",
    description: "网关要求额外的动态验证码，以确认本次登录。",
    step: 1,
  },
  authenticated: {
    kicker: "03 / TUNNEL",
    title: "准备建立隧道",
    description: "身份验证已完成，最后一步是配置本地安全链路。",
    step: 2,
  },
  "tunnel-starting": {
    kicker: "03 / NEGOTIATING",
    title: "正在建立隧道",
    description: "正在请求系统权限并协商网络配置，请稍候。",
    step: 2,
  },
  connected: {
    kicker: "03 / ONLINE",
    title: "私有链路已就绪",
    description: "公司内网流量现在通过加密隧道传输。",
    step: 2,
  },
  "tunnel-lost": {
    kicker: "03 / OFFLINE",
    title: "隧道已断开",
    description: "连接中断，客户端正在尝试恢复；恢复失败时可手动重连或重新登录。",
    step: 2,
  },
};

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) {
    throw new Error(`缺少界面元素：${id}`);
  }
  return found as T;
}

const configForm = element<HTMLFormElement>("config-form");
const loginForm = element<HTMLFormElement>("login-form");
const challengeForm = element<HTMLFormElement>("challenge-form");
const stateBadge = element<HTMLDivElement>("state-badge");
const stateLabel = element<HTMLSpanElement>("state-text");
const errorMessage = element<HTMLDivElement>("error-message");
const statusMessage = element<HTMLDivElement>("status-message");
const passwordInput = element<HTMLInputElement>("password");
const cancelButton = element<HTMLButtonElement>("cancel-button");
const actionButtons = Array.from(document.querySelectorAll<HTMLButtonElement>("button"))
  .filter((button) => button !== cancelButton);

function renderState(state: ConnectionState): void {
  stateBadge.dataset.state = state;
  stateLabel.textContent = stateText[state];
}

function setStage(stage: string): void {
  const copy = stageCopy[stage] ?? stageCopy.disconnected;
  configForm.hidden = stage !== "disconnected";
  element("certificate-section").hidden = stage !== "certificate";
  loginForm.hidden = stage !== "ready";
  challengeForm.hidden = stage !== "challenge";
  element("authenticated-section").hidden = !["authenticated", "tunnel-starting"].includes(stage);
  element("connected-section").hidden = stage !== "connected";
  element("stage-kicker").textContent = copy.kicker;
  element("connection-title").textContent = copy.title;
  element("stage-description").textContent = copy.description;
  // 断线阶段由连接状态说话：徽标颜色和文案交给 vpn-state 事件。
  if (stage !== "tunnel-lost") {
    stateBadge.dataset.state = stage === "authenticated" ? "connected" : stage;
    stateLabel.textContent = stageText[stage] ?? stateText.disconnected;
  }

  document.querySelectorAll<HTMLLIElement>("[data-step]").forEach((step, index) => {
    step.classList.toggle("is-active", index === copy.step);
    step.classList.toggle("is-complete", index < copy.step);
    if (index === copy.step) step.setAttribute("aria-current", "step");
    else step.removeAttribute("aria-current");
  });

  const stageElement = stageElements[stage];
  if (stageElement) {
    element(stageElement).scrollIntoView({ block: "nearest" });
  }
}

function showError(error: unknown): void {  const message = typeof error === "object" && error !== null && "message" in error
    ? String((error as VpnError).message)
    : String(error);
  errorMessage.textContent = message;
  errorMessage.hidden = false;
  statusMessage.textContent = "操作未完成";
  statusMessage.dataset.tone = "error";
  errorMessage.scrollIntoView({ block: "center" });
}

function setBusy(busy: boolean): void {
  actionButtons.forEach((button) => {
    button.disabled = busy;
  });
}

async function perform(action: () => Promise<void>, pendingMessage: string): Promise<void> {
  setBusy(true);
  errorMessage.hidden = true;
  statusMessage.textContent = pendingMessage;
  statusMessage.dataset.tone = "pending";
  try {
    await action();
  } catch (error) {
    showError(error);
  } finally {
    setBusy(false);
  }
}

function showAuthView(view: AuthView): void {
  statusMessage.textContent = view.message;
  statusMessage.dataset.tone = ["authenticated", "connected"].includes(view.stage)
    ? "success"
    : "pending";
  setStage(view.stage);
}

/// 断线横幅：把原因和后续动作说清楚，不让用户猜。
function showDisconnectBanner(lost: TunnelLost): void {
  element<HTMLElement>("disconnect-title").textContent = lost.willRetry
    ? "隧道已断开，正在自动重连"
    : "隧道已断开，自动重连失败";
  element<HTMLElement>("disconnect-detail").textContent = lost.willRetry
    ? `第 ${lost.attempt} 次重连尝试中。${lost.reason}`
    : `${lost.reason}。请检查网络后点“立即重连”；会话失效时用“重置连接”重新登录。`;
  element<HTMLDivElement>("disconnect-banner").hidden = false;
}

function hideDisconnectBanner(): void {
  element<HTMLDivElement>("disconnect-banner").hidden = true;
}

async function loadSavedPassword(): Promise<void> {
  const host = element<HTMLInputElement>("gateway-host").value;
  const port = Number(element<HTMLInputElement>("gateway-port").value);
  const username = element<HTMLInputElement>("username").value;
  if (!host || !username || !port) {
    return;
  }

  const saved = await invoke<{ password: string | null }>("load_saved_credential", {
    host,
    port,
    username,
  });
  if (saved.password !== null) {
    passwordInput.value = saved.password;
    element<HTMLInputElement>("remember-password").checked = true;
    statusMessage.textContent = "已从系统密钥环载入匹配凭据";
  }
}

configForm.addEventListener("submit", (event) => {
  event.preventDefault();
  passwordInput.value = "";
  element<HTMLInputElement>("remember-password").checked = false;
  const data = new FormData(configForm);
  const config = {
    name: String(data.get("profileName") ?? ""),
    host: String(data.get("gatewayHost") ?? ""),
    port: Number(data.get("gatewayPort")),
    protocol: "sslVpn",
    tlsPolicy: String(data.get("tlsPolicy") ?? "modern"),
  };

  void perform(async () => {
    const certificate = await invoke<CertificateView>("probe_gateway", { config });
    element("certificate-subject").textContent = certificate.subject;
    element("certificate-cn").textContent = certificate.commonName ?? "未提供";
    element("certificate-fingerprint").textContent = certificate.fingerprint;
    statusMessage.textContent = "请核对证书指纹后再继续";
    setStage("certificate");
  }, "正在连接网关并读取证书…");
});

element("trust-button").addEventListener("click", () => {
  void perform(async () => {
    showAuthView(await invoke<AuthView>("trust_and_discover"));
    await loadSavedPassword();
  }, "正在发现网关认证能力…");
});

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const username = element<HTMLInputElement>("username").value;
  const password = passwordInput.value;
  const verifyCode = element<HTMLInputElement>("verify-code").value;
  const remember = element<HTMLInputElement>("remember-password").checked;

  void perform(async () => {
    try {
      showAuthView(await invoke<AuthView>("login_gateway", {
        username,
        password,
        verifyCode,
        remember,
      }));
    } finally {
      passwordInput.value = "";
    }
  }, "正在提交凭据，请稍候…");
});

element("username").addEventListener("change", () => {
  void loadSavedPassword().catch(showError);
});

challengeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const codeInput = element<HTMLInputElement>("challenge-code");
  const code = codeInput.value;

  void perform(async () => {
    try {
      showAuthView(await invoke<AuthView>("challenge_gateway", { code }));
    } finally {
      codeInput.value = "";
    }
  }, "正在提交二次认证…");
});

element("tunnel-button").addEventListener("click", () => {
  void perform(async () => {
    showAuthView(await invoke<AuthView>("start_tunnel"));
  }, "正在请求管理员权限并建立隧道…");
});

element("stop-tunnel-button").addEventListener("click", () => {
  void perform(async () => {
    showAuthView(await invoke<AuthView>("stop_tunnel"));
  }, "正在断开隧道并清理网络配置…");
});

element("reconnect-button").addEventListener("click", () => {
  void perform(async () => {
    hideDisconnectBanner();
    showAuthView(await invoke<AuthView>("start_tunnel"));
  }, "正在重新建立隧道…");
});

element("logout-button").addEventListener("click", () => {
  void perform(async () => {
    await invoke("logout_gateway");
    passwordInput.value = "";
    element<HTMLInputElement>("remember-password").checked = false;
    statusMessage.textContent = "会话已注销";
    statusMessage.dataset.tone = "success";
    setStage("disconnected");
  }, "正在注销网关会话…");
});

cancelButton.addEventListener("click", () => {
  void perform(async () => {
    await invoke("cancel_gateway");
    statusMessage.textContent = "已清空本地会话";
    statusMessage.dataset.tone = "success";
    passwordInput.value = "";
    element<HTMLInputElement>("remember-password").checked = false;
    setStage("disconnected");
  }, "正在清空本地会话…");
});

async function initialize(): Promise<void> {
  const unlistenState = await listen<ConnectionState>("vpn-state", (event) => {
    renderState(event.payload);
  });
  const unlistenStage = await listen<string>("vpn-stage", (event) => {
    setStage(event.payload);
    if (event.payload === "connected" || event.payload === "disconnected") {
      hideDisconnectBanner();
    }
  });
  const unlistenTunnel = await listen<{ interface: string; address: string }>(
    "tunnel-ready",
    (event) => {
      element("tunnel-address").textContent = event.payload.address;
      element("tunnel-interface").textContent = `TUN / ${event.payload.interface}`;
      statusMessage.textContent = "隧道已连接，可以访问公司内网";
      statusMessage.dataset.tone = "success";
      hideDisconnectBanner();
    },
  );
  const unlistenLost = await listen<TunnelLost>("tunnel-lost", (event) => {
    showDisconnectBanner(event.payload);
  });
  window.addEventListener("beforeunload", () => {
    unlistenState();
    unlistenStage();
    unlistenTunnel();
    unlistenLost();
  });

  renderState(await invoke<ConnectionState>("get_core_state"));
  setStage("disconnected");
}

void initialize().catch(showError);
