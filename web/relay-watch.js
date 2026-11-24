(() => {
  'use strict';

  const statuses = {
    disabled: ['未开启', 'neutral'],
    scheduled: ['等待检查', 'history'],
    complete: ['自动恢复已开启', 'success'],
    paused: ['自动恢复已暂停', 'history'],
    waiting: ['等待其他任务', 'history'],
    restoring: ['正在自动恢复', 'running'],
    error: ['本次检查失败', 'error'],
  };
  const timeFormat = new Intl.DateTimeFormat('zh-CN', {dateStyle: 'short', timeStyle: 'short'});
  const displayTime = (seconds) => Number.isFinite(seconds) && seconds > 0 && seconds < 8.64e12
    ? timeFormat.format(new Date(seconds * 1000)) : '—';

  window.createRelayWatchView = ({request, sessionExpired, onBatchChange = () => {}}) => {
    const names = ['Badge', 'Capability', 'Content', 'Form', 'Enabled', 'Site', 'Interval', 'SiteHint', 'Save', 'Check',
      'Notice', 'Status', 'Message', 'LastScan', 'NextScan', 'Count', 'Results', 'ResultsHint', 'Rows', 'AdminLink',
      'Retries', 'RetryRows', 'Events', 'EventRows'];
    const ui = Object.fromEntries(names.map((name) => [name, document.getElementById(`watch${name}`)]));
    let context = {supported: null, online: false, visible: false, savedSites: new Map(), sitesStatus: 'idle'};
    let watch = null;
    let dirty = false;
    let busy = false;
    let reading = false;
    let timer;
    let revision = 0;
    let notice = '';
    let readError = '';
    let siteSignature = '';
    let rowsSignature = '';
    let batchSignature = '';

    const visible = () => context.supported === true && context.online && context.visible && !document.hidden;
    const canUse = () => visible() && watch && !busy;

    function renderSites(siteId) {
      const sites = [...context.savedSites.values()];
      const missing = siteId && !context.savedSites.has(siteId) ? siteId : '';
      const signature = JSON.stringify([sites, missing]);
      if (signature !== siteSignature) {
        siteSignature = signature;
        ui.Site.replaceChildren(new Option('请选择站点', ''), ...sites.map((site) => new Option(site.base_url, site.id)));
        if (missing) ui.Site.add(new Option('此站点当前不可用', missing));
      }
      ui.Site.value = siteId;
    }

    function renderResults() {
      const accounts = watch.accounts;
      const signature = JSON.stringify(accounts);
      if (signature !== rowsSignature) {
        rowsSignature = signature;
        const rows = document.createDocumentFragment();
        for (const account of accounts) {
          const row = document.createElement('tr');
          const name = document.createElement('strong');
          name.className = 'record-email';
          name.textContent = account.email || '邮箱待核对';
          const id = document.createElement('span');
          id.className = 'record-detail';
          id.textContent = `站内账号 #${account.account_id}`;
          row.insertCell().append(name, id);
          row.insertCell().textContent = account.reason || '请核对账号状态';
          rows.append(row);
        }
        ui.Rows.replaceChildren(rows);
      }
      ui.Results.hidden = accounts.length === 0;
      const count = watch.last_counts.unauthorized;
      ui.ResultsHint.textContent = count > accounts.length ? `显示 ${accounts.length} / ${count} 个账号。` : '';
      ui.AdminLink.hidden = true;
      ui.AdminLink.removeAttribute('href');
      const site = context.savedSites.get(watch.site_id);
      if (!site || !accounts.length) return;
      try {
        const base = new URL(site.base_url);
        if (base.protocol === 'https:' && !base.username && !base.password) {
          ui.AdminLink.href = new URL('/admin/accounts', base.origin).href;
          ui.AdminLink.hidden = false;
        }
      } catch {
        // The saved address is not a usable link.
      }
    }

    function render() {
      ui.Capability.hidden = context.supported === true;
      ui.Capability.textContent = context.supported === false
        ? '当前后台未加载自动检查与恢复。重新启动本机工具后刷新网页。' : '正在检查本机后台。';
      ui.Content.hidden = context.supported !== true;
      ui.Badge.hidden = ui.Content.hidden || !watch;
      ui.Status.hidden = !watch;

      if (!dirty) {
        ui.Enabled.checked = watch?.enabled === true;
        ui.Interval.value = watch?.interval_minutes ?? 5;
      }
      renderSites(dirty ? ui.Site.value : watch?.site_id || '');
      const siteReady = context.sitesStatus === 'ready';
      ui.SiteHint.textContent = !siteReady && context.sitesStatus === 'error' ? '暂时无法读取已保存的中转站。'
        : siteReady && context.savedSites.size === 0 ? '请先在上方连接并保存一个中转站。' : '';
      ui.Enabled.disabled = ui.Interval.disabled = !canUse();
      ui.Site.disabled = !canUse() || !siteReady || Boolean(watch?.active_batch_id);
      ui.Save.disabled = !canUse() || !dirty || (ui.Enabled.checked && (!siteReady || !context.savedSites.has(ui.Site.value)))
        || !ui.Interval.validity.valid;
      ui.Check.disabled = !canUse() || !watch?.enabled || watch.running || watch.status === 'paused' || !siteReady || !context.savedSites.has(watch.site_id);
      ui.Notice.textContent = readError || notice || (watch ? '' : '正在读取自动恢复设置。');
      if (!watch) return;

      const [label, color] = watch.active_batch_id ? ['正在自动恢复', 'running']
        : watch.running ? ['正在检查', 'running'] : statuses[watch.status] || statuses.disabled;
      ui.Badge.textContent = label;
      ui.Badge.className = `badge ${color}`;
      ui.Message.textContent = watch.message;
      ui.LastScan.textContent = displayTime(watch.last_scan_at);
      ui.NextScan.textContent = watch.active_batch_id ? '当前恢复结束后安排' : watch.running ? '检查中' : displayTime(watch.next_scan_at);
      ui.Count.textContent = watch.last_success_at ? String(watch.last_counts.unauthorized) : '—';
      renderResults();
      renderRetries();
      const events = [...(watch.events || [])].reverse();
      ui.EventRows.replaceChildren(...events.map((entry) => {
        const row = document.createElement('li');
        row.textContent = `${displayTime(entry.time)} · ${entry.account_id ? `账号 #${entry.account_id} · ` : ''}${entry.message}`;
        return row;
      }));
    }

    function renderRetries() {
      const rows = (watch.retry_accounts || []).filter((row) => row.site_id === watch.site_id);
      ui.Retries.hidden = rows.length === 0;
      ui.RetryRows.replaceChildren(...rows.map((account) => {
        const row = document.createElement('tr');
        const name = document.createElement('strong');
        name.className = 'record-email';
        name.textContent = account.email || '邮箱待核对';
        const id = document.createElement('span');
        id.className = 'record-detail';
        id.textContent = `站内账号 #${account.account_id}`;
        row.insertCell().append(name, id);
        const description = document.createElement('span');
        description.className = 'record-detail';
        description.textContent = account.reason + (account.next_retry_at ? ` 下次尝试：${displayTime(account.next_retry_at)}` : '');
        const retry = document.createElement('button');
        retry.type = 'button';
        retry.className = 'button button-secondary';
        retry.textContent = '允许重新尝试';
        retry.dataset.accountId = String(account.account_id);
        retry.disabled = !canUse() || !watch.enabled || watch.status === 'paused' || Boolean(watch.active_batch_id);
        retry.addEventListener('click', () => {
          if (!retry.disabled) change('retry', {site_id: watch.site_id, account_id: account.account_id}, '已允许重新尝试，将先核对账号当前状态。');
        });
        row.insertCell().append(description, retry);
        return row;
      }));
    }

    function apply(data) {
      if (typeof data?.watch?.enabled !== 'boolean' || !Array.isArray(data.watch.accounts) ||
          !Number.isInteger(data.watch.last_counts?.unauthorized)) throw new Error('Invalid watch status');
      watch = data.watch;
      readError = '';
      // Reauthorization polling stops when idle. Detect both a newly started
      // automatic batch and its completion, including batches between polls.
      const signature = JSON.stringify([watch.active_batch_id, (watch.events || []).filter((event) =>
        ['start', 'result', 'restart'].includes(event.kind)).slice(-1)]);
      if (signature !== batchSignature) {
        batchSignature = signature;
        onBatchChange();
      }
    }

    function schedule(delay = 5000) {
      clearTimeout(timer);
      if (visible() && !reading && !busy) timer = setTimeout(refresh, delay);
    }

    async function refresh() {
      if (!visible() || reading || busy) return;
      reading = true;
      const started = revision;
      try {
        const data = await request('/api/relay/watch');
        if (started === revision) apply(data);
      } catch (error) {
        if (started === revision && !sessionExpired(error)) readError = '暂时无法读取自动恢复状态，会自动重试。';
      } finally {
        reading = false;
        render();
        schedule();
      }
    }

    async function change(action, body, successText) {
      if (!canUse()) return;
      busy = true;
      const started = ++revision;
      notice = '正在提交…';
      render();
      try {
        const data = await request(`/api/relay/watch-${action}`, {method: 'POST', body});
        if (started !== revision) return;
        apply(data);
        if (action === 'configure') dirty = false;
        notice = successText;
      } catch (error) {
        if (started === revision && !sessionExpired(error)) {
          notice = Number.isInteger(error.status) && error.status > 0 && error.message
            ? error.message : '暂时无法确认操作结果，请查看自动恢复状态。';
        }
      } finally {
        if (started === revision) busy = false;
        render();
        schedule(0);
      }
    }

    const edit = () => { dirty = true; notice = ''; render(); };
    ui.Enabled.addEventListener('change', edit);
    ui.Site.addEventListener('change', edit);
    ui.Interval.addEventListener('input', edit);
    ui.Form.addEventListener('submit', (event) => {
      event.preventDefault();
      if (ui.Save.disabled) return;
      change('configure', {enabled: ui.Enabled.checked, site_id: ui.Site.value || null, interval_minutes: Number(ui.Interval.value)}, '已保存自动恢复设置。');
    });
    ui.Check.addEventListener('click', () => {
      if (!ui.Check.disabled) change('check', {}, '已请求立即检查。');
    });
    document.addEventListener('visibilitychange', () => { render(); schedule(0); });

    return {
      detectionSettings() {
        if (!canUse()) throw new Error('请等待自动检查区加载完成后再启动检测。');
        if (context.sitesStatus !== 'ready' || !context.savedSites.has(ui.Site.value)) {
          throw new Error('请先在上方“自动检查与恢复”选择已保存的中转站，再点击导入并启动检测。');
        }
        const interval = Number(ui.Interval.value);
        if (!Number.isInteger(interval) || interval < 1 || interval > 60) {
          throw new Error('请在自动检查区填写 1 至 60 分钟的检测间隔。');
        }
        if (watch?.active_batch_id) throw new Error('当前正在恢复账号，请等待结束后再导入。');
        return {site_id: ui.Site.value, interval_minutes: interval};
      },
      imported(data) {
        if (data.watch) {
          apply(data);
          dirty = false;
        }
        render();
        schedule(0);
      },
      update(next) {
        const wasVisible = visible();
        context = next;
        render();
        if (visible() !== wasVisible) schedule(0);
      },
      resetSession() {
        revision += 1;
        watch = null;
        busy = false;
        dirty = false;
        notice = '';
        readError = '';
        batchSignature = '';
        clearTimeout(timer);
      },
    };
  };
})();
