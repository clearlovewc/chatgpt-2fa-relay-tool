(() => {
  'use strict';

  const labels = {
    queued: ['排队中', 'neutral'], running: ['处理中', 'running'],
    success: ['已恢复并启用调用', 'success'], error: ['未恢复', 'error'],
    skipped: ['已停止', 'neutral'], interrupted: ['已中断', 'history'], unknown: ['待核对', 'history'],
  };
  const message = (error, fallback) => Number.isInteger(error?.status) && error.message ? error.message : fallback;
  const accountId = (value) => Number.isSafeInteger(value) && value > 0;
  const displayTime = (seconds) => Number(seconds) > 0 ? new Date(seconds * 1000).toLocaleString('zh-CN') : '';

  window.createRelayReauthView = ({request, onChange, sessionExpired, getDetectionSettings, onImported}) => {
    const elements = [
      'Capability', 'Content', 'SearchForm', 'Search', 'SearchButton', 'Notice', 'CandidateList',
      'CandidateTable', 'CandidateRows', 'Pages', 'PageInfo', 'Prev', 'Next', 'Submit', 'Selected',
      'ClearSelection', 'Progress', 'ProgressBadge', 'ProgressMessage', 'Stop', 'Cancel', 'ResultRows',
      'ImportCapability', 'ImportForm', 'ImportInput', 'ImportSave', 'ImportStart', 'ImportNotice',
      'ImportedList', 'ImportedCount', 'ImportedRows',
    ];
    const ui = Object.fromEntries(elements.map((name) => [name, document.getElementById(`reauth${name}`)]));
    const selected = new Map();
    let context = {supported: null, online: false, visible: false, canSend: false, connection: null};
    let filter = '';
    let historyFocus = null;
    let candidates = null;
    let batch = null;
    let batchFingerprint = '';
    let checkedBatch = false;
    let busy = '';
    let notice = '';
    let revision = 0;
    let checking = false;
    let timer;
    let submission = null;
    let importNotice = '';
    let importReadError = '';
    let importedRecords = [];
    let importBusy = false;
    let recordsRevision = 0;
    let importEpoch = 0;

    const running = () => batch?.status === 'running';
    const available = () => context.supported === true && context.online && context.canSend;
    const canSelect = () => available() && checkedBatch && context.connection && !busy && !importBusy && !running() && !submission;
    const post = (path, body) => request(`/api/relay/${path}`, {method: 'POST', body, timeout: 30000});

    function render() {
      ui.Capability.hidden = context.supported === true;
      ui.Capability.textContent = context.supported === false
        ? '当前后台没有加载重授权功能。重新启动本机工具并刷新网页。'
        : '正在检查本机后台。';
      ui.Content.hidden = context.supported !== true;
      renderImport();
      ui.Search.disabled = !canSelect();
      ui.SearchButton.disabled = !canSelect();
      ui.SearchButton.textContent = busy === 'search' ? '正在查询…' : '查询失效账号';
      ui.Notice.textContent = notice || (!context.connection
        ? '请先连接要恢复账号的中转站。'
        : !checkedBatch ? '正在核对上次任务。' : '');
      ui.CandidateList.hidden = !candidates;
      ui.Prev.disabled = !canSelect() || !candidates || candidates.page <= 1;
      ui.Next.disabled = !canSelect() || !candidates || candidates.page >= candidates.pages;
      ui.Submit.disabled = !((canSelect() && selected.size) || (available() && submission && !busy && !running()));
      ui.Submit.textContent = busy === 'submit' ? '正在提交…' : submission ? '核对并重试提交' : '重授权并启用调用';
      ui.Selected.textContent = `已选 ${selected.size} 个账号`;
      ui.ClearSelection.hidden = selected.size === 0;
      ui.ClearSelection.disabled = !canSelect();
      const allowCancel = running() && context.online && !busy;
      ui.Stop.hidden = !running() || !!batch?.stop_requested || !batch?.counts?.queued;
      ui.Cancel.hidden = !running();
      ui.Stop.disabled = !allowCancel;
      ui.Cancel.disabled = !allowCancel;
      for (const check of ui.CandidateRows.querySelectorAll('input[type="checkbox"]')) {
        check.checked = selected.has(Number(check.value));
        check.disabled = !canSelect() || (!check.checked && selected.size >= 500);
      }
    }

    function renderImport() {
      const supported = context.importSupported === true;
      ui.ImportCapability.hidden = supported;
      ui.ImportCapability.textContent = '当前后台未加载账号资料导入，请重新启动本机工具后刷新网页。';
      const enabled = supported && available() && checkedBatch && !busy && !importBusy && !running() && !submission;
      ui.ImportInput.disabled = !supported || importBusy;
      ui.ImportSave.disabled = ui.ImportStart.disabled = !enabled || !ui.ImportInput.value.trim();
      ui.ImportSave.textContent = importBusy ? '正在保存…' : '导入账号';
      ui.ImportNotice.textContent = importNotice || importReadError;
    }

    function renderImportedRecords() {
      ui.ImportedCount.textContent = `可用账号资料（${importedRecords.length} 个）`;
      ui.ImportedList.hidden = importedRecords.length === 0;
      ui.ImportedRows.replaceChildren(...importedRecords.map((item) => {
        const row = document.createElement('tr');
        row.insertCell().textContent = item.email;
        row.insertCell().textContent = item.source === 'manual_import' ? '手动导入' : '更换记录';
        row.insertCell().textContent = displayTime(item.finished_at);
        return row;
      }));
    }

    async function refreshImportedRecords() {
      if (context.importSupported !== true || !context.online || !context.visible) return;
      const epoch = importEpoch;
      const currentRead = ++recordsRevision;
      try {
        const data = await request('/api/relay/reauth-history');
        if (epoch !== importEpoch || currentRead !== recordsRevision) return;
        if (!Array.isArray(data?.records)) throw new Error('Invalid account records');
        importedRecords = data.records;
        importReadError = '';
        renderImportedRecords();
      } catch (error) {
        if (epoch === importEpoch && currentRead === recordsRevision && !sessionExpired(error)) {
          importReadError = message(error, '暂时无法读取已保存的账号资料。');
        }
      } finally {
        renderImport();
      }
    }

    async function importAccounts(startDetection) {
      if (ui.ImportSave.disabled) return;
      const payload = {lines: ui.ImportInput.value};
      if (startDetection) {
        try {
          Object.assign(payload, getDetectionSettings(), {start_detection: true});
        } catch (error) {
          importNotice = error.message;
          renderImport();
          document.getElementById('relayWatch').scrollIntoView({block: 'start'});
          return;
        }
      }
      const epoch = importEpoch;
      importBusy = true;
      importNotice = '';
      render();
      onChange();
      try {
        const data = await post('import-accounts', payload);
        if (epoch !== importEpoch) return;
        if (!Array.isArray(data?.records) || !['imported', 'updated', 'unchanged'].every((key) => Number.isSafeInteger(data[key]))) {
          throw new Error('Invalid import result');
        }
        ui.ImportInput.value = '';
        selected.clear();
        candidates = null;
        renderCandidates();
        importNotice = `已保存：新增 ${data.imported} 个，更新 ${data.updated} 个，未变化 ${data.unchanged} 个。`;
        importNotice += data.detection_error ? ` ${data.detection_error}`
          : data.detection_started ? ' 已启动检测，结果和恢复进度显示在上方自动检查区。'
            : ' 自动检测会使用这些资料；也可在上方开启或立即检查。';
        onImported?.(data);
        await refreshImportedRecords();
      } catch (error) {
        if (epoch === importEpoch && !sessionExpired(error)) {
          importNotice = message(error, '尚未确认导入结果，请查看已保存资料后重试。');
        }
      } finally {
        delete payload.lines;
        if (epoch === importEpoch) {
          importBusy = false;
          render();
          onChange();
          if (context.connection && canSelect()) search();
        }
      }
    }

    async function readCandidates(connection, page, email = '') {
      const data = await post('reauth-candidates', {connection_id: connection, page, ...(email ? {email} : {})});
      if (!Array.isArray(data?.items) || data.page !== page || !Number.isSafeInteger(data.pages) || data.pages < 1 || data.pages > 10000) {
        throw new Error('Invalid candidates');
      }
      return data;
    }

    function accountCell(row, item) {
      const cell = row.insertCell();
      const name = document.createElement('strong');
      name.className = 'record-email';
      name.textContent = item.email || '邮箱待核对';
      const id = document.createElement('span');
      id.className = 'record-detail';
      id.textContent = `站内账号 #${item.account_id}`;
      cell.append(name, id);
    }

    function workspaceText(value) {
      if (!value?.id) return '工作空间待核对';
      const plan = typeof value.plan === 'string' && value.plan ? `（${value.plan}）` : '';
      return `${value.id}${plan}`;
    }

    function renderCandidates() {
      const rows = document.createDocumentFragment();
      const items = (candidates?.items || []).filter((item) => !filter || (item.email || '').toLowerCase() === filter);
      for (const item of items) {
        if (!accountId(item.account_id)) continue;
        const row = document.createElement('tr');
        const history = item.history;
        const choice = row.insertCell();
        if (item.eligible === true && typeof history?.id === 'string' && history.id) {
          const check = document.createElement('input');
          check.type = 'checkbox';
          check.value = String(item.account_id);
          check.setAttribute('aria-label', `选择 ${item.email}，站内账号 ${item.account_id}，${workspaceText(item.workspace)}`);
          check.addEventListener('change', () => {
            if (check.checked && selected.size < 500) selected.set(item.account_id, history.id);
            else selected.delete(item.account_id);
            render();
          });
          choice.append(check);
        } else {
          choice.textContent = '—';
          selected.delete(item.account_id);
        }
        accountCell(row, item);
        row.insertCell().textContent = workspaceText(item.workspace);
        const record = row.insertCell();
        const historyTime = displayTime(history?.finished_at || history?.updated_at || history?.created_at);
        const source = history?.source === 'manual_import' ? '手动导入' : '更换记录';
        record.textContent = item.eligible
          ? (historyTime ? `${source} · ${historyTime}` : source)
          : (item.reason || '没有匹配的可用账号资料，请先导入。');
        if (item.eligible && historyFocus?.email === String(item.email).toLowerCase() && historyFocus.id !== history.id) {
          const latest = document.createElement('span');
          latest.className = 'record-detail';
          latest.textContent = '此邮箱有更新的账号资料，勾选将使用最新资料。';
          record.append(latest);
        }
        if (history?.id && selected.has(item.account_id) && selected.get(item.account_id) !== history.id) {
          selected.delete(item.account_id);
        }
        rows.append(row);
      }
      ui.CandidateTable.hidden = !rows.childElementCount;
      ui.CandidateRows.replaceChildren(rows);
      ui.Pages.hidden = !candidates || candidates.pages < 2;
      ui.PageInfo.textContent = candidates ? `第 ${candidates.page} / ${candidates.pages} 页` : '';
      return items.length;
    }

    function showBatch(next) {
      const fingerprint = JSON.stringify(next);
      if (fingerprint === batchFingerprint) return;
      batchFingerprint = fingerprint;
      batch = next;
      ui.Progress.hidden = !batch;
      if (!batch) {
        ui.ResultRows.replaceChildren();
        return;
      }
      const counts = batch.counts || {};
      const total = counts.total || batch.items?.length || 0;
      ui.ProgressBadge.className = `badge ${running() ? 'running' : counts.success === total && total ? 'success' : 'history'}`;
      ui.ProgressBadge.textContent = running() ? '处理中' : batch.status === 'interrupted' ? '已中断' : '已结束';
      ui.ProgressMessage.textContent = batch.message || `已恢复 ${counts.success || 0} / ${total} 个账号。`;
      const rows = document.createDocumentFragment();
      for (const item of batch.items || []) {
        const row = document.createElement('tr');
        accountCell(row, item);
        row.insertCell().textContent = workspaceText(item.workspace);
        const result = row.insertCell();
        const [label, color] = labels[item.status] || labels.unknown;
        const badge = document.createElement('span');
        badge.className = `badge ${color}`;
        badge.textContent = label;
        const detail = document.createElement('span');
        detail.className = 'record-detail';
        detail.textContent = item.message || '';
        result.append(badge, detail);
        rows.append(row);
      }
      ui.ResultRows.replaceChildren(rows);
    }

    function refreshSoon(delay = 1300) {
      clearTimeout(timer);
      if (context.supported === true && context.online && context.visible && !document.hidden) {
        timer = setTimeout(refreshBatch, delay);
      }
    }

    async function refreshBatch() {
      if (checking || busy === 'submit' || busy === 'stop' || busy === 'cancel') {
        refreshSoon();
        return;
      }
      checking = true;
      const currentRevision = revision;
      try {
        const data = await request('/api/relay/reauth-batch');
        if (currentRevision !== revision) return;
        if (!Object.hasOwn(data, 'batch')) throw new Error('Invalid batch');
        const firstCheck = !checkedBatch;
        checkedBatch = true;
        showBatch(data.batch);
        if (submission && batch && batch.id !== submission.previousBatchId &&
            batch.items?.length === submission.body.items.length && submission.body.items.every((item) =>
              batch.items.some((saved) => item.account_id === saved.account_id && item.record_id === saved.record_id))) {
          submission = null;
          selected.clear();
          notice = '已读回后台保存的任务，请查看重授权进度。';
        }
        if (firstCheck && historyFocus && canSelect() && !candidates) search();
      } catch (error) {
        if (currentRevision !== revision || sessionExpired(error)) return;
        if (!checkedBatch) notice = message(error, '暂时无法读取重授权进度，正在重试。');
      } finally {
        checking = false;
        render();
        onChange();
        if (running() || !checkedBatch || submission) refreshSoon();
      }
    }

    async function search(page = 1) {
      if (!canSelect()) return;
      const cid = context.connection;
      const email = filter;
      const currentRevision = revision;
      const stillCurrent = () => currentRevision === revision && cid === context.connection && context.online;
      let scanned = 0;
      let pages = 0;
      busy = 'search';
      notice = '';
      if (email) {
        candidates = null;
        renderCandidates();
      }
      render();
      try {
        if (email) {
          const matches = new Map();
          let number = 1;
          do {
            notice = `正在按邮箱查询，第 ${number}${pages ? ` / ${pages}` : ''} 页。`;
            render();
            const data = await readCandidates(cid, number, email);
            if (!stillCurrent()) return;
            for (const item of data.items) {
              if (accountId(item.account_id) && (item.email || '').toLowerCase() === email) matches.set(item.account_id, item);
            }
            scanned = number;
            pages = data.pages;
            number += 1;
          } while (number <= pages);
          for (const id of selected.keys()) {
            if (!matches.has(id)) selected.delete(id);
          }
          candidates = {items: Array.from(matches.values()), page: 1, pages: 1};
        } else {
          const data = await readCandidates(cid, page);
          if (!stillCurrent()) return;
          candidates = data;
        }
        const found = renderCandidates();
        notice = found ? '' : !email && candidates.pages > 1
          ? '本页没有授权失效的账号，可继续翻页。'
          : '没有找到符合条件的失效账号。';
      } catch (error) {
        if (stillCurrent() && !sessionExpired(error)) {
          if (email) selected.clear();
          const incomplete = email ? `邮箱查询尚未完成，已读取 ${scanned}${pages ? ` / ${pages}` : ''} 页。` : '';
          notice = incomplete + message(error, '无法读取失效账号，请检查中转站连接后重试。');
        }
      } finally {
        if (currentRevision === revision) {
          busy = '';
          render();
        }
      }
    }

    async function submit() {
      if (busy || running() || !available() || (!submission && (!canSelect() || !selected.size))) return;
      if (!submission) {
        submission = {
          previousBatchId: batch?.id,
          body: {connection_id: context.connection, request_id: window.crypto.randomUUID(),
                 items: Array.from(selected, ([account_id, record_id]) => ({account_id, record_id}))},
        };
      }
      const currentRevision = ++revision;
      busy = 'submit';
      notice = '正在提交所选站内账号。';
      render();
      onChange();
      try {
        const data = await post('reauth-submit', submission.body);
        if (currentRevision !== revision) return;
        if (!data?.batch?.id) throw new Error('Invalid batch');
        showBatch(data.batch);
        submission = null;
        selected.clear();
        notice = '';
      } catch (error) {
        if (currentRevision !== revision || sessionExpired(error)) return;
        notice = message(error, '未收到提交结果，正在查询已保存的重授权任务。');
        if (Number.isInteger(error.status) && error.status < 500) submission = null;
      } finally {
        if (currentRevision === revision) {
          busy = '';
          render();
          onChange();
          refreshSoon(100);
        }
      }
    }

    async function stop(path) {
      if (busy || !running() || !context.online) return;
      const currentRevision = ++revision;
      busy = path;
      render();
      try {
        const data = await post(`reauth-${path}`, {batch_id: batch.id});
        if (currentRevision === revision && data?.batch?.id === batch?.id) showBatch(data.batch);
      } catch (error) {
        if (currentRevision === revision && !sessionExpired(error)) {
          notice = message(error, '尚未确认停止结果，正在查询当前进度。');
        }
      } finally {
        if (currentRevision === revision) {
          busy = '';
          render();
          refreshSoon(100);
        }
      }
    }

    ui.ImportInput.addEventListener('input', renderImport);
    ui.ImportForm.addEventListener('submit', (event) => {
      event.preventDefault();
      importAccounts(false);
    });
    ui.ImportStart.addEventListener('click', () => importAccounts(true));
    window.addEventListener('pagehide', () => { ui.ImportInput.value = ''; });

    ui.SearchForm.addEventListener('submit', (event) => {
      event.preventDefault();
      if (!canSelect()) return;
      const next = ui.Search.value.trim().toLowerCase();
      if (next !== filter) {
        filter = next;
        historyFocus = null;
        selected.clear();
        candidates = null;
        renderCandidates();
      }
      search();
    });
    ui.Prev.addEventListener('click', () => { if (candidates?.page > 1) search(candidates.page - 1); });
    ui.Next.addEventListener('click', () => { if (candidates?.page < candidates?.pages) search(candidates.page + 1); });
    ui.Submit.addEventListener('click', submit);
    ui.ClearSelection.addEventListener('click', () => { selected.clear(); render(); });
    ui.Stop.addEventListener('click', () => stop('stop'));
    ui.Cancel.addEventListener('click', () => stop('cancel'));
    document.addEventListener('visibilitychange', () => refreshSoon(0));

    return {
      refresh: () => refreshSoon(0),
      hasWork: () => running() || Boolean(submission) || importBusy,
      update(next) {
        const before = context;
        context = next;
        if (before.connection !== context.connection || before.supported !== context.supported) {
          revision += 1;
          busy = '';
          submission = null;
          selected.clear();
          candidates = null;
          notice = '';
          renderCandidates();
        }
        render();
        const opened = context.visible && !before.visible;
        if (opened || before.supported !== context.supported || before.online !== context.online) refreshSoon(0);
        if (!context.visible) ui.ImportInput.value = '';
        if (opened || before.importSupported !== context.importSupported || before.online !== context.online) refreshImportedRecords();
        if (historyFocus && canSelect() && !candidates && (opened || before.connection !== context.connection || before.canSend !== context.canSend)) {
          search();
        }
      },
      resetSession() {
        revision += 1;
        busy = '';
        submission = null;
        checkedBatch = false;
        notice = '';
        importEpoch += 1;
        importBusy = false;
        importNotice = '';
        importReadError = '';
        importedRecords = [];
        ui.ImportInput.value = '';
        renderImportedRecords();
        showBatch(null);
        refreshSoon(0);
      },
      fromHistory(record) {
        if (busy === 'search') {
          revision += 1;
          busy = '';
        }
        historyFocus = {id: record.id, email: record.email.toLowerCase()};
        filter = historyFocus.email;
        ui.Search.value = record.email;
        selected.clear();
        candidates = null;
        notice = '';
        renderCandidates();
        render();
        if (canSelect()) search();
        requestAnimationFrame(() => document.getElementById('relayReauth').scrollIntoView({block: 'start'}));
      },
    };
  };
})();
