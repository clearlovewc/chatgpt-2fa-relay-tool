(() => {
  'use strict';

  const maxAccounts = 500;
  const rowStatus = {
    idle: ['待授权', 'neutral'],
    starting: ['正在准备授权', 'running'],
    pending: ['等待本人授权', 'history'],
    finishing: ['正在提交', 'running'],
    success: ['成功', 'success'],
    unknown: ['结果待核对', 'history'],
    failed: ['失败', 'error'],
    exists: ['账号已存在', 'history'],
    review: ['工作空间待核对', 'history'],
    canceled: ['已取消', 'neutral'],
  };
  const emailPattern = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/u;
  const isEmail = (email) => typeof email === 'string' && email.length <= 320 && emailPattern.test(email);
  const hasId = (id) => Number.isSafeInteger(id) && id > 0;
  const identifier = (value) => typeof value === 'string' && value.length > 0;
  const safeMessage = (error, fallback) => Number.isInteger(error?.status) && error.message ? error.message : fallback;

  function parseEmails(text) {
    const emails = new Map();
    let ignored = 0;
    for (const line of text.split(/\r\n|\n|\r/)) {
      if (!line.trim()) continue;
      const text = line.trim();
      const first = text.indexOf('----');
      const last = text.lastIndexOf('----');
      const email = (first < 0 ? text : text.slice(0, first)).trim();
      let login;
      if (first >= 0) {
        const password = text.slice(first + 4, last);
        const secret = text.slice(last + 4).replace(/\s/g, '').toUpperCase().replace(/=+$/, '');
        if (first === last || !password || password.length > 4096 || !/^[A-Z2-7]{16,128}$/.test(secret)) {
          ignored += 1;
          continue;
        }
        login = {password, secret};
      }
      if (isEmail(email)) emails.set(email.toLowerCase(), {email, login});
      else ignored += 1;
    }
    return {emails, ignored};
  }

  function openAIUrl(value) {
    if (typeof value !== 'string' || value.includes('#')) return '';
    try {
      const url = new URL(value);
      if (url.origin === 'https://auth.openai.com' && url.pathname === '/oauth/authorize' && !url.username && !url.password) return url.href;
    } catch {
      // An invalid response does not produce a clickable authorization link.
    }
    return '';
  }

  window.createRelayView = ({request, reconnect}) => {
    const ids = {
      capability: 'relayCapability', controls: 'relayControls',
      connectionForm: 'relayConnectionForm', baseUrl: 'relayBaseUrl', adminKey: 'relayAdminKey',
      savedSiteFields: 'relaySavedSiteFields', savedSite: 'relaySavedSite', savedSitesHint: 'relaySavedSitesHint',
      rememberSiteOption: 'relayRememberSiteOption', rememberSite: 'relayRememberSite',
      deleteSite: 'relayDeleteSite', reloadSites: 'relayReloadSites',
      connect: 'relayConnect', disconnect: 'relayDisconnect', connectionBadge: 'relayConnectionBadge',
      connectionMessage: 'relayConnectionMessage', settingsFields: 'relaySettingsFields', settingsNotice: 'relaySettingsNotice',
      nativeLink: 'relayNativeLink', syncModels: 'relaySyncModels', modelNotice: 'relayModelNotice',
      importForm: 'relayImportForm', importStart: 'relayImportStart', emails: 'relayEmails', count: 'relayCount',
      queueMessage: 'relayQueueMessage', batchStatus: 'relayBatchStatus', stopBatch: 'relayStopBatch',
      table: 'relayTable', rows: 'relayRows', active: 'relayActive',
      activeTitle: 'relayActiveTitle', activeEmail: 'relayActiveEmail', activeSettings: 'relayActiveSettings',
      activeWorkspace: 'relayActiveWorkspace', popupStatus: 'relayPopupStatus',
      authLink: 'relayAuthLink', check: 'relayCheck', manual: 'relayManual', callbackMode: 'relayCallbackMode',
      finishForm: 'relayFinishForm', callbackUrl: 'relayCallbackUrl',
      finish: 'relayFinish', cancel: 'relayCancel', flowMessage: 'relayFlowMessage',
    };
    const ui = Object.fromEntries(Object.entries(ids).map(([key, id]) => [key, document.getElementById(id)]));
    const accounts = new Map();
    let supported = null;
    let settingsSupported = false;
    let loginSupported = false;
    let sitesSupported = false;
    let reauthSupported = null;
    let watchSupported = null;
    let importSupported = null;
    let savedSites = new Map();
    let selectedSiteId = '';
    let sitesStatus = 'idle';
    let sitesRevision = 0;
    const settingsView = window.createRelaySettings?.({syncCatalog});
    let online = false;
    let connection = null;
    let active = null;
    let batch = null;
    let pageSuspended = false;
    let pageRevision = 0;
    let busy = '';
    let visible = false;
    let checking = false;
    let statusRevision = 0;
    let autoTimer;
    const reauthView = window.createRelayReauthView?.({request, onChange: render, sessionExpired: localSessionExpired,
      getDetectionSettings: () => watchView.detectionSettings(), onImported: (data) => watchView?.imported(data)});
    const watchView = window.createRelayWatchView?.({request, sessionExpired: localSessionExpired,
      onBatchChange: () => reauthView?.refresh()});

    const canRequest = () => supported === true && online && !busy && !pageSuspended;
    const canStart = () => canRequest() && settingsSupported && connection && !active && !reauthView?.hasWork();
    const canStartManually = () => canStart() && !batch;
    const call = (route, body, timeout) => request(`/api/relay/${route}`, {method: 'POST', body, timeout});
    const setText = (node, value) => { if (node.textContent !== value) node.textContent = value; };
    const connectionMessage = (message) => setText(ui.connectionMessage, message);
    const flowMessage = (message) => setText(ui.flowMessage, message);
    const queueMessage = (message) => setText(ui.queueMessage, message);

    function action(label, onClick, disabled = false) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'text-button table-action';
      button.textContent = label;
      button.disabled = disabled;
      button.addEventListener('click', onClick);
      return button;
    }

    function renderRows() {
      const rows = document.createDocumentFragment();
      for (const account of accounts.values()) {
        const tr = document.createElement('tr');
        const email = tr.insertCell();
        const emailLabel = document.createElement('strong');
        emailLabel.className = 'record-email';
        emailLabel.textContent = account.email;
        email.append(emailLabel);

        const status = tr.insertCell();
        const badge = document.createElement('span');
        let [label, color] = rowStatus[account.callbackBusy && account === active ? 'finishing' : account.status];
        if (account.status === 'pending' && account.automaticLogin) {
          [label, color] = account.loginStage === 'waiting_user' ? ['等待补充操作', 'history'] : ['自动登录中', 'running'];
        }
        badge.className = `badge ${color}`;
        badge.textContent = label;
        status.append(badge);
        if (account.detail) {
          const detail = document.createElement('p');
          detail.className = 'record-detail relay-row-detail';
          detail.textContent = account.detail;
          status.append(detail);
        }
        if (hasId(account.accountId) && ['exists', 'review', 'unknown'].includes(account.status)) {
          const accountReference = document.createElement('p');
          accountReference.className = 'record-detail relay-row-detail';
          accountReference.textContent = `中转站账号 ID ${account.accountId}。可到站内按 ID 查看。`;
          status.append(accountReference);
        }

        const operation = tr.insertCell();
        if (account.status === 'unknown' && account.flowId && account.connectionId === connection?.id) {
          operation.append(action('查询本次结果', () => checkResult(account), !canRequest() || Boolean(active)));
        } else if (account.status === 'review') {
          operation.append(action('重新核对', () => start(account), !canStartManually()));
        } else if (account === active && account.status === 'pending') {
          operation.append(action('查看授权步骤', () => ui.activeTitle.focus(), !canRequest()));
        } else if (['idle', 'failed', 'canceled'].includes(account.status)) {
          operation.append(action('开始授权并入站', () => start(account), !canStartManually()));
        }
        rows.append(tr);
      }
      ui.rows.replaceChildren(rows);
      ui.table.hidden = accounts.size === 0;
      setText(ui.count, `${accounts.size} 个账号`);
    }

    function render() {
      const canSend = canRequest();
      const connected = Boolean(connection);
      ui.capability.hidden = supported === true;
      setText(ui.capability, supported === false
        ? '本机后台仍在运行旧版。请先保存手头工作，按 Ctrl+Alt+Delete 选择「注销」并重新登录，或正常重启电脑后登录。'
          + '登录后重新打开本机工具。若未设置登录自启，请双击「启动2FA工具.cmd」。'
        : '正在检查本机服务是否支持上号。');
      ui.controls.hidden = supported !== true;
      ui.controls.disabled = supported !== true || !online;
      const savedSite = savedSites.get(selectedSiteId);
      const editingConnection = canSend && !connected && settingsSupported && sitesStatus !== 'loading';
      ui.savedSiteFields.hidden = !sitesSupported;
      ui.savedSite.disabled = !editingConnection;
      ui.rememberSiteOption.hidden = !sitesSupported;
      ui.rememberSite.disabled = !editingConnection;
      ui.baseUrl.disabled = !editingConnection;
      ui.baseUrl.readOnly = Boolean(savedSite);
      ui.adminKey.disabled = !editingConnection;
      ui.adminKey.required = !savedSite;
      ui.adminKey.placeholder = savedSite ? '已保存，可输入新 Key' : '';
      ui.deleteSite.hidden = !savedSite || connected;
      ui.deleteSite.disabled = !editingConnection;
      ui.reloadSites.hidden = !sitesSupported || sitesStatus !== 'error' || connected;
      ui.reloadSites.disabled = !editingConnection;
      setText(ui.savedSitesHint, !settingsSupported ? '' : !sitesSupported
        ? '重新启动本机工具后可保存站点，本次仍可临时连接。'
        : sitesStatus === 'loading' ? '正在读取已保存的中转站。'
          : sitesStatus === 'error' ? '未能读取已保存的中转站，可重试或填写站点信息。'
            : savedSite ? '留空使用已保存的 Key。填写新 Key 并勾选记住，连接成功后会更新。'
              : '勾选记住即可在本机加密保存 Key，下次选择站点即可连接。');
      ui.connect.hidden = connected;
      ui.connect.disabled = !editingConnection;
      setText(ui.connect, busy === 'connect' ? '正在连接并读取目录…' : '连接中转站');
      ui.disconnect.hidden = !connected;
      ui.disconnect.disabled = !canSend || !connected || reauthView?.hasWork();
      setText(ui.disconnect, busy === 'disconnect' ? '正在断开…' : '断开中转站');
      ui.connectionBadge.className = `badge ${connected ? 'success' : 'neutral'}`;
      setText(ui.connectionBadge, connected ? '已连接' : '未连接');
      settingsView?.setEnabled(Boolean(canStartManually()));
      ui.importStart.disabled = !canStartManually();
      ui.stopBatch.hidden = !batch || batch.index + 1 >= batch.rows.length;
      if (batch) setText(ui.batchStatus, `接入进度 ${batch.index + 1} / ${batch.rows.length}。提供完整三段信息的账号会自动登录。`);
      ui.settingsFields.hidden = !settingsSupported;
      const notice = !settingsSupported
        ? '请重新启动本机后台，再刷新页面。也可以先填写站点地址，打开中转站的账号管理页。'
        : !connected
          ? '连接中转站后可设置账号。'
          : batch
            ? '本次加入的账号使用同一套设置。'
            : active
              ? '当前账号的设置已保存。本次授权结束后可继续编辑。'
            : '';
      setText(ui.settingsNotice, notice);
      updateNativeLink();
      setText(ui.syncModels, busy === 'catalog' ? '正在同步…' : '从站点同步模型目录');

      ui.active.hidden = !active;
      if (active) {
        setText(ui.activeEmail, active.email);
        setText(ui.activeSettings, active.settingsSummary);
        const {expected_workspace_id: workspaceId, workspace_policy: workspacePolicy} = active.settings;
        const target = workspacePolicy === 'business' ? '目标 Business / Team 工作空间' : '目标工作空间';
        const workspaceHint = workspaceId
          ? `目标工作空间 ID ${workspaceId}。入站前会核对实际授权的 ID。`
          : active.automaticLogin ? '自动排除个人账户，选择唯一的其他工作空间并继续。若有多个团队且未指定目标，浏览器会等待选择。'
            : `未指定工作空间 ID。如果 OpenAI 显示多个工作空间，请选择${target}。`;
        ui.activeWorkspace.hidden = false;
        setText(ui.activeWorkspace, workspaceHint);
      }
      const canComplete = active && canSend && !active.callbackBusy && !active.cancelUnconfirmed;
      if (canComplete) ui.authLink.href = active.authUrl;
      else ui.authLink.removeAttribute('href');
      ui.authLink.setAttribute('aria-disabled', String(!canComplete));
      ui.authLink.hidden = Boolean(active?.automaticLogin);
      ui.manual.hidden = Boolean(active?.automaticLogin);
      ui.callbackUrl.disabled = !canComplete;
      ui.finish.disabled = !canComplete;
      ui.cancel.disabled = !canComplete;
      ui.check.hidden = !(active?.autoCallback || active?.cancelUnconfirmed);
      ui.check.disabled = !canSend || checking;
      setText(ui.finish, busy === 'finish' ? '正在提交…' : '提交回调地址并添加账号');
      setText(ui.cancel, busy === 'cancel' ? '正在取消…' : '取消本次授权');
      renderRows();
      reauthView?.update({supported: reauthSupported, online, visible, connection: connection?.id || null,
                          canSend: canSend && !active && !batch, importSupported});
      watchView?.update({supported: watchSupported, online, visible: visible && !pageSuspended, savedSites, sitesStatus});
      scheduleAutoCheck();
    }

    function updateNativeLink() {
      let href = '';
      try {
        const base = new URL(ui.baseUrl.value.trim());
        if (base.protocol === 'https:' && !base.username && !base.password && !base.search && !base.hash &&
            ['', '/', '/api/v1', '/api/v1/', '/api/v1/admin', '/api/v1/admin/'].includes(base.pathname)) {
          href = new URL('/admin/accounts', base.origin).href;
        }
      } catch {
        // The user is still filling in the HTTPS address.
      }
      if (href) ui.nativeLink.href = href;
      else ui.nativeLink.removeAttribute('href');
      ui.nativeLink.hidden = !href;
    }

    ui.baseUrl.addEventListener('input', updateNativeLink);
    ui.baseUrl.addEventListener('change', updateNativeLink);

    function selectSavedSite(id) {
      const site = savedSites.get(id);
      if (site || selectedSiteId) ui.baseUrl.value = site?.base_url ?? '';
      selectedSiteId = site?.id ?? '';
      ui.savedSite.value = selectedSiteId;
      ui.adminKey.value = '';
      ui.rememberSite.checked = true;
      updateNativeLink();
    }

    function applySavedSites(data, preferredId) {
      if (!Array.isArray(data?.sites)) throw new Error('Invalid saved relay list');
      savedSites = new Map(data.sites.filter(site => identifier(site?.id) && identifier(site?.base_url))
        .map(({id, base_url}) => [id, {id, base_url}]));
      ui.savedSite.replaceChildren(new Option('新建连接', ''), ...[...savedSites.values()]
        .map(site => new Option(site.base_url, site.id)));
      const nextId = savedSites.has(preferredId) ? preferredId : '';
      if (nextId !== selectedSiteId || nextId) selectSavedSite(nextId);
      sitesStatus = 'ready';
    }

    function resetSavedSites() {
      sitesRevision += 1;
      sitesStatus = 'idle';
      savedSites.clear();
      selectSavedSite('');
      ui.savedSite.replaceChildren(new Option('新建连接', ''));
    }

    async function loadSavedSites(preferredId = null) {
      if (!sitesSupported || !online || pageSuspended || sitesStatus === 'loading') return;
      const revision = ++sitesRevision;
      sitesStatus = 'loading';
      render();
      try {
        const data = await request('/api/relay/sites');
        if (revision === sitesRevision) applySavedSites(data, preferredId ?? data?.last_site_id);
      } catch (error) {
        if (revision === sitesRevision) {
          sitesStatus = 'error';
          localSessionExpired(error);
        }
      } finally {
        if (revision === sitesRevision) render();
      }
    }

    function loadSitesForView() {
      if (visible && sitesStatus === 'idle' && !busy) void loadSavedSites(selectedSiteId || null);
    }

    ui.savedSite.addEventListener('change', () => {
      if (!canRequest() || connection) return;
      selectSavedSite(ui.savedSite.value);
      connectionMessage('');
      render();
    });
    ui.reloadSites.addEventListener('click', () => {
      if (canRequest() && !connection) void loadSavedSites(selectedSiteId || (ui.baseUrl.value ? '' : null));
    });

    async function syncCatalog() {
      if (!canStart()) return;
      const requestConnection = connection;
      busy = 'catalog';
      setText(ui.modelNotice, '正在从中转站读取目录。');
      render();
      try {
        const data = await call('catalog', {connection_id: requestConnection.id}, 30000);
        if (requestConnection !== connection) return;
        if (!settingsView.setCatalog(data)) setText(ui.modelNotice, '目录数据不完整，已保留当前设置。请稍后重试。');
      } catch (error) {
        if (!connectionExpired(error) && !localSessionExpired(error)) {
          setText(ui.modelNotice, safeMessage(error, '目录同步失败，已保留当前设置。'));
        }
      } finally {
        busy = '';
        render();
      }
    }

    function closeActive() {
      if (active) active.authUrl = '';
      active = null;
      ui.callbackUrl.value = '';
      setText(ui.popupStatus, '');
      flowMessage('');
    }

    const mayHaveAutoSubmitted = (account) => account.autoCallback && account.authOpened;

    function recordUnknown(account, message, accountId) {
      account.status = 'unknown';
      account.detail = message;
      if (hasId(accountId)) account.accountId = accountId;
    }

    function applyExistingAccount(account, outcome, message, accountId) {
      if (outcome !== 'already_exists' && outcome !== 'workspace_review') return false;
      const unrestricted = account.settings?.workspace_policy === 'any' && account.settings?.expected_workspace_id === '';
      const duplicate = outcome === 'already_exists' && (hasId(accountId) || unrestricted);
      account.status = duplicate ? 'exists' : 'review';
      account.accountId = hasId(accountId) ? accountId : undefined;
      if (duplicate) {
        account.detail = '已确认站内已有该账号，本次已跳过添加。';
      } else {
        const reason = outcome === 'workspace_review' && typeof message === 'string' && message
          ? message : '请在中转站核对同邮箱账号的工作空间。';
        account.detail = `${reason} 修正后点「重新核对」，可再查一次站内记录。`;
      }
      return true;
    }

    function clearConnection(message) {
      stopBatch('中转站连接已结束。后续授权已停止。');
      const previousId = connection?.id;
      if (active) {
        active.status = active.callbackBusy || mayHaveAutoSubmitted(active) ? 'unknown' : 'failed';
        active.detail = '中转站连接已结束。重新连接后可开始新的授权。';
      }
      closeActive();
      connection = null;
      for (const account of accounts.values()) {
        delete account.login;
        if (account.requiresLogin && account.status === 'idle') account.detail = '登录信息已清除，请重新粘贴此账号。';
      }
      ui.adminKey.value = '';
      settingsView?.clear();
      connectionMessage(message);
      for (const account of accounts.values()) {
        if (account.status === 'unknown' && account.connectionId === previousId) {
          account.detail = '旧连接已结束。请到中转站的账号列表核对结果，避免重复添加。';
        }
      }
    }

    function resetSession() {
      online = false;
      reauthView?.resetSession();
      watchView?.resetSession();
      resetSavedSites();
      clearConnection('本机页面会话已更新，请重新连接中转站。');
      render();
    }

    function localSessionExpired(error) {
      if (error?.outcome || error?.status !== 401 || !error.message?.startsWith('页面会话已失效')) return false;
      resetSession();
      reconnect();
      return true;
    }

    function connectionExpired(error) {
      if (error?.outcome !== 'connection_expired') return false;
      clearConnection(safeMessage(error, '中转站连接已过期，请重新连接。'));
      return true;
    }

    function recordExpiredFlow(account, error) {
      if (account.callbackBusy || mayHaveAutoSubmitted(account)) {
        account.status = 'unknown';
        account.detail = '本机授权记录已过期，请到中转站核对账号列表。';
        account.flowId = '';
      } else {
        account.status = 'failed';
        account.detail = safeMessage(error, '本次授权已过期，请重新开始。');
      }
      if (account === active) closeActive();
    }

    ui.connectionForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!canRequest() || !settingsSupported || connection || sitesStatus === 'loading') return;
      const site = savedSites.get(selectedSiteId);
      const baseUrl = site?.base_url ?? ui.baseUrl.value.trim();
      const adminKey = ui.adminKey.value.trim();
      ui.adminKey.value = '';
      const useSavedKey = Boolean(site && !adminKey);
      if (!baseUrl || (!adminKey && !useSavedKey)) {
        connectionMessage('请填写站点地址和管理员 Key。');
        return;
      }
      const remember = sitesSupported && ui.rememberSite.checked;
      const payload = useSavedKey ? {site_id: site.id} : {base_url: baseUrl, admin_key: adminKey};
      if (!useSavedKey && sitesSupported) payload.remember = remember;
      busy = 'connect';
      connectionMessage('正在验证管理员 Key，读取分组、代理和模型。');
      render();
      try {
        const data = await call('connect', payload, 30000);
        if (!identifier(data?.connection_id) || !settingsSupported || !settingsView.setCatalog(data, {reset: true})) {
          connectionMessage('未取得完整的连接或入站目录，请重新连接。');
          return;
        }
        connection = {id: data.connection_id};
        await settingsView.loadPreset(baseUrl);
        const savedId = identifier(data.saved_site_id) ? data.saved_site_id : '';
        const savedNotice = savedId && !useSavedKey && remember ? '已保存此站点。' : '';
        connectionMessage(`已读取 ${data.groups.length} 个 OpenAI 分组和 ${data.proxies.length} 个代理。${savedNotice}`);
        if (sitesSupported && (savedId || useSavedKey)) await loadSavedSites(savedId || site.id);
      } catch (error) {
        if (!localSessionExpired(error)) connectionMessage(safeMessage(error, '连接失败，请检查站点地址和管理员 Key。'));
      } finally {
        busy = '';
        render();
        loadSitesForView();
      }
    });

    ui.deleteSite.addEventListener('click', async () => {
      if (!canRequest() || connection || !sitesSupported || !selectedSiteId || sitesStatus === 'loading') return;
      busy = 'delete-site';
      render();
      try {
        applySavedSites(await call('delete-site', {site_id: selectedSiteId}), '');
        connectionMessage('已删除此站点的保存信息。');
      } catch (error) {
        if (!localSessionExpired(error)) connectionMessage(safeMessage(error, '未能删除保存信息，请稍后重试。'));
      } finally {
        busy = '';
        render();
        loadSitesForView();
      }
    });

    ui.disconnect.addEventListener('click', async () => {
      if (!canRequest() || !connection || reauthView?.hasWork()) return;
      stopBatch('后续授权已停止。');
      busy = 'disconnect';
      render();
      try {
        await call('disconnect', {connection_id: connection.id});
        if (active && !active.callbackBusy && !mayHaveAutoSubmitted(active)) {
          active.status = 'canceled';
          closeActive();
        }
        clearConnection('已断开中转站。');
      } catch (error) {
        if (!connectionExpired(error) && !localSessionExpired(error)) {
          connectionMessage(safeMessage(error, '未能确认中转站是否已断开，请重新尝试。'));
        }
      } finally {
        busy = '';
        render();
      }
    });

    ui.importForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const shouldStart = event.submitter === ui.importStart;
      if (supported !== true || !online || (shouldStart && !canStartManually())) return;
      const {emails, ignored} = parseEmails(ui.emails.value);
      if (!loginSupported && [...emails.values()].some(item => item.login)) {
        queueMessage('当前后台尚未加载自动登录功能，请重新启动本机工具后提交。');
        return;
      }
      ui.emails.value = '';
      const added = [];
      let duplicate = 0;
      let overLimit = 0;
      for (const [key, item] of emails) {
        const {email, login} = item;
        const existing = accounts.get(key);
        if (existing && login && ['idle', 'failed', 'canceled', 'review'].includes(existing.status)) {
          Object.assign(existing, {login, requiresLogin: true, status: 'idle', detail: ''});
          added.push(existing);
        } else if (existing) duplicate += 1;
        else if (accounts.size >= maxAccounts) overLimit += 1;
        else {
          const account = {email, login, requiresLogin: Boolean(login), status: 'idle', detail: ''};
          accounts.set(key, account);
          added.push(account);
        }
      }
      const messages = [];
      if (added.length) messages.push(`已添加 ${added.length} 个邮箱`);
      if (duplicate) messages.push(`已忽略 ${duplicate} 个重复邮箱`);
      if (ignored) messages.push(`已忽略 ${ignored} 行无效内容`);
      if (overLimit) messages.push(`列表最多保留 ${maxAccounts} 个邮箱`);
      const message = messages.length ? `${messages.join('，')}。` : '请先输入至少一个有效邮箱。';
      queueMessage(message);
      if (shouldStart && added.length) {
        const prepared = settingsView.read((problem) => queueMessage(message + problem));
        if (prepared) {
          settingsView.savePreset();
          batch = {rows: added, index: 0, prepared, tab: added.some(item => !item.requiresLogin) ? prepareAuthTab() : null, tabUsed: false};
          advanceBatch();
          return;
        }
      }
      renderRows();
    });

    function stopBatch(message, keepCurrentTab = false) {
      if (!batch) return;
      const stopped = batch;
      batch = null;
      if (!keepCurrentTab && !stopped.tabUsed) stopped.tab?.close();
      setText(ui.batchStatus, message);
    }

    ui.stopBatch.addEventListener('click', () => {
      stopBatch('已停止后续授权。当前账号仍可继续完成。', true);
      render();
    });

    function advanceBatch() {
      if (!batch || active || busy || checking || pageSuspended) return;
      while (batch.index < batch.rows.length) {
        const account = batch.rows[batch.index];
        if (account.status === 'success' || account.status === 'exists') {
          batch.index += 1;
          continue;
        }
        if (account.status === 'idle' && canStart()) {
          start(account, batch);
        } else {
          stopBatch(`连续授权已暂停。${account.email} · ${rowStatus[account.status][0]}。其余账号留在列表中。`);
          render();
        }
        return;
      }
      stopBatch('本次连续授权已完成。');
      render();
    }

    function prepareAuthTab() {
      let tab = null;
      try {
        tab = window.open('about:blank', '_blank');
        if (!tab) return null;
        tab.opener = null;
        if (tab.opener !== null) throw new Error('Could not detach the authorization tab');
        tab.document.title = '正在准备 OpenAI 授权';
        tab.document.body.textContent = '正在准备 OpenAI 授权，请稍等。';
        return tab;
      } catch {
        tab?.close();
        return null;
      }
    }

    function openAuthTab(tab, url) {
      try {
        if (!tab || tab.closed) return false;
        tab.location.replace(url);
        return true;
      } catch {
        return false;
      }
    }

    async function start(account, ownerBatch = null) {
      if (!canStart() || (ownerBatch ? ownerBatch !== batch : Boolean(batch)) ||
          !['idle', 'failed', 'canceled', 'review'].includes(account.status)) return;
      const rechecking = account.status === 'review';
      const prepared = ownerBatch ? ownerBatch.prepared : settingsView.read(queueMessage);
      if (!prepared) return;
      const {settings, summary} = prepared;
      if (account.requiresLogin && !account.login) {
        account.status = 'failed';
        account.detail = '本次登录信息已清除。请重新粘贴此账号的三段信息后开始。';
        stopBatch('本次队列已暂停，请补充该账号的登录信息。');
        render();
        return;
      }
      if (!ownerBatch) settingsView.savePreset();
      const tab = account.login || rechecking ? null : ownerBatch ? ownerBatch.tab : prepareAuthTab();
      const revision = pageRevision;
      let tabOpened = false;
      const requestConnection = connection;
      account.status = 'starting';
      account.detail = '';
      account.flowId = '';
      account.accountId = undefined;
      account.settings = settings;
      account.settingsSummary = summary;
      if (rechecking) queueMessage(`正在重新核对 ${account.email} 的站内记录。`);
      else if (ownerBatch) queueMessage(`正在为 ${account.email} 准备授权。`);
      else queueMessage('');
      busy = 'start';
      render();
      try {
        const payload = {connection_id: requestConnection.id, email: account.email, settings};
        if (account.login) payload.login = account.login;
        let data;
        try {
          data = await call('start', payload);
        } finally {
          delete account.login;
          delete payload.login;
        }
        const url = openAIUrl(data?.auth_url);
        if (requestConnection !== connection) {
          account.status = 'failed';
          account.detail = '中转站连接已结束，请重新连接。';
          return;
        }
        if (!identifier(data?.flow_id) || !url) {
          account.status = 'failed';
          account.detail = '未取得完整的 OpenAI 授权链接，请重新开始。';
          return;
        }
        account.status = 'pending';
        account.flowId = data.flow_id;
        account.connectionId = requestConnection.id;
        account.authUrl = url;
        account.autoCallback = data.auto_callback === true;
        account.automaticLogin = data.automatic_login === true;
        account.loginStage = account.automaticLogin ? 'launching' : '';
        if (account.requiresLogin && !account.automaticLogin) {
          await call('cancel', {connection_id: requestConnection.id, flow_id: data.flow_id});
          account.status = 'failed';
          account.detail = '后台没有启动自动登录，请更新后台后重试。';
          return;
        }
        account.autoPaused = false;
        account.callbackBusy = false;
        account.cancelUnconfirmed = false;
        tabOpened = !account.automaticLogin && revision === pageRevision && openAuthTab(tab, url);
        if (ownerBatch && tabOpened) ownerBatch.tabUsed = true;
        account.authOpened = account.automaticLogin || tabOpened;
        active = account;
        setText(ui.authLink, tabOpened ? '重新打开 OpenAI 授权页' : '打开 OpenAI 授权页');
        setText(ui.popupStatus, account.automaticLogin ? '已启动独立 Chrome 窗口，正常登录步骤会自动完成。'
          : rechecking
          ? '站内核对已完成。如需继续添加这个账号，请打开下方的 OpenAI 授权页。'
          : tabOpened ? '' : '授权标签页未能自动打开。请点击下方链接继续。');
        ui.manual.open = !account.autoCallback;
        setText(ui.callbackMode, account.automaticLogin
          ? '授权回调会自动接收并入站，无需复制或回填链接。'
          : account.autoCallback
          ? '账号本人同意后会自动添加。授权完成后回这里查看结果。'
          : data.auto_callback === false
            ? '本机回调端口不可用。请完成授权，再手动粘贴回调地址。'
            : '请完成授权，再手动粘贴回调地址。');
        flowMessage('');
      } catch (error) {
        const expired = connectionExpired(error) || localSessionExpired(error);
        if (!applyExistingAccount(account, error?.outcome, error?.message, error?.accountId)) {
          if (error?.outcome === 'unknown') {
            recordUnknown(account, safeMessage(error, '请到中转站核对本次结果。'), error?.accountId);
          } else {
            account.status = 'failed';
            account.detail = expired ? '请重新连接中转站，然后开始授权。' : safeMessage(error, '没收到授权链接，请重新开始。');
          }
        }
      } finally {
        if (!tabOpened && (!ownerBatch || (!ownerBatch.tabUsed && (ownerBatch !== batch || account.status !== 'exists')))) {
          tab?.close();
        }
        if (rechecking) queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
        busy = '';
        render();
        if (active === account && visible && !document.hidden) ui.activeTitle.focus();
        advanceBatch();
      }
    }

    function acceptConfirmedAccount(account, data) {
      if (data?.status !== 'success' || !hasId(data.account_id) || !isEmail(data.email) || data.email.toLowerCase() !== account.email.toLowerCase()) return false;
      const expectedId = account.settings?.expected_workspace_id?.toLowerCase();
      const businessOnly = account.settings?.workspace_policy === 'business';
      const workspace = data.workspace;
      const id = typeof workspace?.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(workspace.id) ? workspace.id : '';
      const plans = new Map([
        ['business', 'Business'], ['team', 'Team'], ['self_serve_business_usage_based', 'Business（按量计费）'],
        ['self_serve_business_prolite', 'Business（Pro Lite）'],
      ]);
      if ((businessOnly && (!id || !plans.has(workspace.plan))) || (expectedId && id.toLowerCase() !== expectedId)) return false;
      account.status = 'success';
      account.detail = `已添加到中转站并核对入站设置。账号 ID ${data.account_id}。`;
      if (id) {
        const type = plans.get(workspace.plan) || (/^[a-z][a-z0-9_-]{0,63}$/u.test(workspace.plan) ? workspace.plan : '');
        account.detail += ` 已核对${type ? ` ${type}` : ''}工作空间，ID ${id}。`;
      }
      return true;
    }

    ui.authLink.addEventListener('click', () => {
      if (active && ui.authLink.hasAttribute('href')) active.authOpened = true;
    });
    ui.authLink.addEventListener('auxclick', (event) => {
      if (event.button === 1 && active && ui.authLink.hasAttribute('href')) active.authOpened = true;
    });

    ui.finishForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!canRequest() || !active || !connection || active.status !== 'pending' || active.callbackBusy || active.cancelUnconfirmed) return;
      const callbackUrl = ui.callbackUrl.value.trim();
      if (!callbackUrl) return;
      ui.callbackUrl.value = '';
      const account = active;
      account.status = 'finishing';
      busy = 'finish';
      flowMessage('正在确认授权并添加账号。');
      render();
      try {
        const data = await call('finish', {connection_id: account.connectionId, flow_id: account.flowId, callback_url: callbackUrl}, 60000);
        if (!applyTerminalStatus(account, data)) {
          recordUnknown(account, '没有收到完整的入站结果，请查询本次结果。', data?.account_id);
          closeActive();
          queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
        }
      } catch (error) {
        if (connectionExpired(error) || localSessionExpired(error)) {
          return;
        }
        if (error?.outcome === 'flow_expired') {
          recordExpiredFlow(account, error);
        } else if (error?.outcome === 'invalid_callback') {
          stopBatch('回调地址与本次授权不符。后续授权已暂停。', true);
          account.status = 'pending';
          flowMessage(safeMessage(error, '请重新粘贴本次授权后的完整地址。'));
        } else if (applyExistingAccount(account, error?.outcome, error?.message, error?.accountId)) {
          closeActive();
        } else if (['unknown', 'busy'].includes(error?.outcome) || !error?.status || error.status >= 500 || (error.status === 409 && !error.outcome)) {
          const detail = error?.outcome ? safeMessage(error, '请查询本次结果。') : '暂未确认入站结果，请查询本次结果。';
          recordUnknown(account, detail, error?.accountId);
          closeActive();
        } else {
          account.status = 'failed';
          account.detail = safeMessage(error, '本次授权失败，请重新开始。');
          closeActive();
        }
        if (!active) queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
      } finally {
        busy = '';
        render();
        if (active === account && visible && !document.hidden) ui.callbackUrl.focus();
        advanceBatch();
      }
    });

    function scheduleAutoCheck() {
      const eligible = active?.status === 'pending' && active.autoCallback && !active.autoPaused &&
        canRequest() && !checking;
      if (!eligible) {
        clearTimeout(autoTimer);
        autoTimer = undefined;
      } else if (autoTimer === undefined) {
        autoTimer = setTimeout(() => {
          autoTimer = undefined;
          refreshActiveStatus();
        }, 2500);
      }
    }

    function applyTerminalStatus(account, result) {
      const message = typeof result?.message === 'string' ? result.message : '';
      if (applyExistingAccount(account, result?.outcome || result?.status, message, result?.account_id)) {
        // A terminal lookup can report a verified duplicate or an account needing review.
      } else if (result?.status === 'failed') {
        // The relay reports a confirmed cancellation as failed with this message.
        account.status = message === '已取消这次授权。' ? 'canceled' : 'failed';
        account.detail = message || '本次授权未完成。';
      } else if (result?.status === 'unknown' || result?.status === 'success') {
        if (result.status === 'unknown' || !acceptConfirmedAccount(account, result)) {
          recordUnknown(account, message || '未收到完整的入站结果，请查询本次结果。', result.account_id);
        }
      } else {
        return false;
      }
      closeActive();
      queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
      return true;
    }

    async function refreshActiveStatus() {
      if (!canRequest() || checking || !connection || active?.status !== 'pending') return;
      if (!active.autoCallback && !active.cancelUnconfirmed) return;
      const account = active;
      const flowId = account.flowId;
      const revision = statusRevision;
      const readIsCurrent = () => active === account && account.flowId === flowId && !busy && revision === statusRevision;
      checking = true;
      ui.check.disabled = true;
      scheduleAutoCheck();
      try {
        const data = await call('status', {connection_id: account.connectionId, flow_id: flowId});
        if (!readIsCurrent()) return;
        const message = typeof data?.message === 'string' ? data.message : '';
        if (data?.status === 'pending') {
          if (account.automaticLogin) {
            account.loginStage = data.login_stage || account.loginStage;
            const progress = typeof data.login_message === 'string' ? data.login_message : '';
            account.detail = progress;
            flowMessage(progress || '自动登录正在进行。');
          }
          if (account.cancelUnconfirmed) flowMessage('授权仍在等待本人同意。可以继续授权或再次取消。');
          else if (!account.automaticLogin && (account.autoPaused || account.callbackBusy)) flowMessage(message || '正在等待账号本人同意。');
          account.autoPaused = false;
          account.callbackBusy = false;
          account.cancelUnconfirmed = false;
          return;
        }
        if (data?.status === 'busy') {
          account.autoPaused = false;
          account.callbackBusy = true;
          flowMessage(message || '本机已收到授权，正在添加账号。');
          return;
        }
        if (!applyTerminalStatus(account, data)) {
          account.autoPaused = true;
          flowMessage('没有收到授权状态。请点击“查询授权状态”。');
        }
      } catch (error) {
        if (!readIsCurrent() || connectionExpired(error) || localSessionExpired(error)) return;
        if (error?.outcome === 'flow_expired') {
          recordExpiredFlow(account, error);
          queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
        } else {
          account.autoPaused = true;
          flowMessage('自动查询暂时中断。请点击“查询授权状态”。');
        }
      } finally {
        checking = false;
        render();
        advanceBatch();
      }
    }

    ui.check.addEventListener('click', refreshActiveStatus);

    async function checkResult(account) {
      if (!canRequest() || active || !connection || account.status !== 'unknown' || account.connectionId !== connection.id) return;
      busy = 'check';
      queueMessage('正在查询本次提交的结果。');
      render();
      try {
        const data = await call('status', {connection_id: account.connectionId, flow_id: account.flowId});
        const message = typeof data?.message === 'string' ? data.message : '';
        if (applyExistingAccount(account, data?.outcome || data?.status, message, data?.account_id)) {
          queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
          return;
        }
        if (data?.status === 'success' && acceptConfirmedAccount(account, data)) {
          queueMessage(`${account.email} · 成功`);
          return;
        }
        if (data?.status === 'failed' && !hasId(account.accountId)) {
          account.status = 'failed';
          account.detail = message || '本次授权未完成，可以重新开始。';
        } else {
          recordUnknown(account, message || '仍未确认入站结果，可稍后再查。', data?.account_id);
        }
        queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
      } catch (error) {
        if (applyExistingAccount(account, error?.outcome, error?.message, error?.accountId)) {
          queueMessage(`${account.email} · ${rowStatus[account.status][0]}`);
        } else if (connectionExpired(error) || localSessionExpired(error)) {
          queueMessage('中转站连接已结束，请核对站内账号列表。');
        } else if (error?.outcome === 'flow_expired') {
          account.detail = '本机授权记录已过期，请到中转站核对账号列表。';
          account.flowId = '';
          queueMessage('本机已无法查询这条记录。');
        } else {
          queueMessage('暂时查不到结果，请在连接恢复后再次查询。');
        }
      } finally {
        busy = '';
        render();
      }
    }

    ui.cancel.addEventListener('click', async () => {
      if (!canRequest() || !active || !connection || active.callbackBusy || active.cancelUnconfirmed) return;
      const account = active;
      stopBatch('取消当前授权时，后续授权也已停止。', true);
      // A status request sent before cancel may arrive after the cancel response.
      statusRevision += 1;
      busy = 'cancel';
      render();
      try {
        const result = await call('cancel', {connection_id: account.connectionId, flow_id: account.flowId});
        if (active !== account) return;
        if (!applyTerminalStatus(account, result)) {
          account.cancelUnconfirmed = true;
          flowMessage('未能确认取消结果，请查询授权状态。');
        }
      } catch (error) {
        if (active !== account || connectionExpired(error) || localSessionExpired(error)) return;
        if (error?.outcome === 'flow_expired') {
          recordExpiredFlow(account, error);
        } else {
          account.cancelUnconfirmed = true;
          account.callbackBusy = error?.outcome === 'busy';
          flowMessage(account.callbackBusy
            ? safeMessage(error, '授权正在处理，请查询授权状态。')
            : '未能确认取消结果，请查询授权状态。');
        }
      } finally {
        busy = '';
        render();
      }
    });

    function clearInputs() {
      ui.adminKey.value = '';
      ui.callbackUrl.value = '';
      ui.emails.value = '';
    }

    window.addEventListener('pagehide', () => {
      pageSuspended = true;
      pageRevision += 1;
      sitesRevision += 1;
      sitesStatus = 'idle';
      stopBatch('此页面已离开。后续授权已停止。');
      render();
      scheduleAutoCheck();
      clearInputs();
      for (const account of accounts.values()) delete account.login;
    });
    window.addEventListener('pageshow', () => {
      if (pageSuspended) {
        pageSuspended = false;
        render();
        loadSitesForView();
      }
    });
    document.addEventListener('visibilitychange', scheduleAutoCheck);
    return {
      setOnline(value) {
        if (online === value) return;
        online = value;
        if (!online) {
          sitesRevision += 1;
          sitesStatus = 'idle';
          ui.adminKey.value = '';
          stopBatch('本机连接中断。后续授权已停止。', true);
        }
        render();
        loadSitesForView();
      },
      resetSession,
      fromHistory: (record) => reauthView?.fromHistory(record),
      setCapability(value, settingsVersion, loginVersion, sitesVersion, reauthVersion, watchVersion, importVersion) {
        const hasSettings = value === true && [1, 2].includes(settingsVersion) && Boolean(settingsView);
        settingsView?.setAccountOptionsCapability(hasSettings && settingsVersion >= 2);
        const hasLogin = Number.isInteger(loginVersion) && loginVersion >= 1;
        const hasSites = hasSettings && sitesVersion === 1;
        const hasReauth = hasSettings && Number.isInteger(reauthVersion) && reauthVersion >= 1;
        const hasWatch = hasSites && watchVersion === 1;
        const hasImport = hasReauth && importVersion === 1;
        if (supported === value && settingsSupported === hasSettings && loginSupported === hasLogin && sitesSupported === hasSites && reauthSupported === hasReauth && watchSupported === hasWatch && importSupported === hasImport) return;
        supported = value;
        reauthSupported = hasReauth;
        watchSupported = hasWatch;
        importSupported = hasImport;
        settingsSupported = hasSettings;
        loginSupported = hasLogin;
        if (sitesSupported !== hasSites) resetSavedSites();
        sitesSupported = hasSites;
        if (value === false || !hasSettings) {
          clearConnection('当前运行的本机服务需要重新启动，才能连接中转站。');
          clearInputs();
        }
        render();
        loadSitesForView();
      },
      setVisible(value) {
        visible = value;
        if (!value) clearInputs();
        render();
        loadSitesForView();
      },
    };
  };
})();
