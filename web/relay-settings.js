(() => {
  'use strict';

  const maxInteger = 2147483647;
  const maxModels = 512;
  const modelPattern = /^[^\s\x00-\x1f\x7f]+$/u;
  const isId = (value) => Number.isSafeInteger(value) && value > 0;
  const isChoice = (entry) => isId(entry?.id) && typeof entry.name === 'string' && Boolean(entry.name.trim());
  const isWorkspaceId = (value) => typeof value === 'string' && (!value || /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value));
  const isModel = (value, wildcard = false) => {
    if (typeof value !== 'string' || value.length > 256 || !modelPattern.test(value)) return false;
    const star = value.indexOf('*');
    return star < 0 || (wildcard && star === value.length - 1);
  };

  function modelRow(kind) {
    const row = document.createElement('div');
    row.className = 'relay-fields relay-mapping-row';
    const [from, to] = ['请求模型', '上游模型'].map((label) => {
      const input = document.createElement('input');
      input.setAttribute('aria-label', `${kind}${label}`);
      input.setAttribute('list', 'relayModelCatalog');
      input.maxLength = 256;
      input.placeholder = label;
      input.autocomplete = 'off';
      input.spellcheck = false;
      return input;
    });
    const arrow = document.createElement('span');
    arrow.setAttribute('aria-hidden', 'true');
    arrow.textContent = '→';
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'text-button';
    remove.textContent = '删除';
    remove.addEventListener('click', () => row.remove());
    row.append(from, arrow, to, remove);
    return {row, firstInput: from};
  }

  window.createRelaySettings = ({syncCatalog}) => {
    const id = (suffix) => document.getElementById(`relay${suffix}`);
    const fields = id('SettingsFields');
    const groupSearch = id('GroupSearch');
    const groupOptions = id('GroupOptions');
    const groupHint = id('GroupHint');
    const groupClear = id('GroupClear');
    const proxy = id('Proxy');
    const modelMode = id('ModelMode');
    const whitelistInput = id('WhitelistInput');
    const whitelistMessage = id('WhitelistMessage');
    const whitelistClear = id('WhitelistClear');
    const whitelistChipList = id('WhitelistModels');
    const modelMappings = id('ModelMappings');
    const compactMappings = id('CompactMappings');
    const tempRules = id('TempRules');
    const rememberPreset = id('RememberPreset');
    const presetStatus = id('PresetStatus');
    const expiresInput = id('ExpiresAt');
    const selectedGroups = new Set();
    const whitelist = new Set();
    let groups = [];
    let proxies = [];
    let defaultGroup = null;
    let modelIds = [];
    let hasCatalog = false;
    let presetKey = '';
    let accountOptionsSupported = false;
    const optionExists = (suffix, value) => typeof value === 'string' && [...id(suffix).options].some((option) => option.value === value);

    function setAccountOptionsCapability(supported) {
      accountOptionsSupported = supported === true;
      id('CodexFingerprintMode').disabled = id('PlanTypeOverride').disabled = !accountOptionsSupported;
      id('AccountOptionsNotice').hidden = accountOptionsSupported;
    }

    function filterGroups() {
      const needle = groupSearch.value.trim().toLocaleLowerCase();
      let shown = 0;
      for (const choice of groupOptions.children) {
        choice.hidden = !choice.textContent.toLocaleLowerCase().includes(needle);
        if (!choice.hidden) shown += 1;
      }
      id('GroupEmpty').textContent = shown ? '' : (needle ? '没有匹配的分组。' : '没有可选的 OpenAI 分组。');
    }

    function refreshGroupSummary() {
      const stale = [...selectedGroups].filter((value) => !groups.some((group) => group.id === value));
      const selection = groups.filter((group) => selectedGroups.has(group.id));
      id('GroupsSummary').textContent = selectedGroups.size ? `已选 ${selectedGroups.size} 个` : '未手动选择';
      groupClear.disabled = !selectedGroups.size;
      if (stale.length) groupHint.textContent = `分组 ID ${stale.join('、')} 已不可用，请取消勾选或重新选择。`;
      else if (selection.length) groupHint.textContent = selection.map((group) => group.name).join('、');
      else if (defaultGroup) groupHint.textContent = `站点将自动分配到 ${defaultGroup.name}（ID ${defaultGroup.id}）。`;
      else groupHint.textContent = hasCatalog ? '此站点没有 OpenAI 默认分组，账号将不加入分组。' : '连接后将显示站点的实际默认分组。';
    }

    function renderGroups() {
      const choices = [...groups];
      for (const value of selectedGroups) {
        if (!groups.some((group) => group.id === value)) choices.push({id: value, name: '已不可用的分组'});
      }
      const labels = choices.map((group) => {
        const label = document.createElement('label');
        label.className = 'relay-checkbox relay-group-choice';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = selectedGroups.has(group.id);
        checkbox.value = String(group.id);
        checkbox.addEventListener('change', () => {
          if (checkbox.checked) selectedGroups.add(group.id);
          else selectedGroups.delete(group.id);
          refreshGroupSummary();
          savePreset();
        });
        const text = document.createElement('span');
        text.textContent = `${group.name} · ID ${group.id}`;
        label.append(checkbox, text);
        return label;
      });
      groupOptions.replaceChildren(...labels);
      filterGroups();
      refreshGroupSummary();
    }

    groupSearch.addEventListener('input', filterGroups);
    groupClear.addEventListener('click', () => {
      selectedGroups.clear();
      renderGroups();
      groupSearch.focus();
      savePreset();
    });

    function renderModels(message = '') {
      const options = modelIds.map((model) => new Option(model, model));
      id('ModelCatalog').replaceChildren(...options);
      id('ModelNotice').textContent = message || (modelIds.length
        ? `目录中有 ${modelIds.length} 个模型，可选择，也可以手工填写。`
        : '目录暂时为空，可以手工填写模型 ID。');
    }

    function setCatalog(data, {reset = false} = {}) {
      if (!Array.isArray(data?.groups) || !data.groups.every(isChoice) ||
          !Array.isArray(data.proxies) || !data.proxies.every(isChoice) || !Array.isArray(data.models) ||
          (data.default_group_id !== null && !data.groups.some((group) => group.id === data.default_group_id))) return false;
      if (reset) clear();
      const previousProxy = proxy.value;
      groups = data.groups;
      proxies = data.proxies;
      defaultGroup = groups.find((group) => group.id === data.default_group_id) || null;
      hasCatalog = true;
      const options = proxies.map((entry) => new Option(`${entry.name} · ID ${entry.id}`, String(entry.id)));
      if (previousProxy && !proxies.some((entry) => String(entry.id) === previousProxy)) {
        options.push(new Option(`已不可用的代理 · ID ${previousProxy}`, previousProxy));
      }
      proxy.replaceChildren(new Option('不使用代理', ''), ...options);
      proxy.value = previousProxy;
      id('ProxyHint').textContent = typeof data.proxies_message === 'string' && data.proxies_message
        ? data.proxies_message : proxies.length ? '' : '站点暂无可用代理。';
      modelIds = [...new Set(data.models.map((model) => typeof model === 'string' ? model : model?.id).filter((model) => isModel(model)))];
      renderModels(typeof data.models_message === 'string' ? data.models_message : '');
      renderGroups();
      return true;
    }

    function setModelMode() {
      id('WhitelistPanel').hidden = modelMode.value !== 'whitelist';
      id('ModelMappingPanel').hidden = modelMode.value !== 'mapping';
      if (modelMode.value === 'mapping' && !modelMappings.children.length) addMapping(modelMappings, '模型', false);
    }
    modelMode.addEventListener('change', setModelMode);
    proxy.addEventListener('change', () => {
      if ([...proxy.options].some((option) => option.value && !proxies.some((entry) => String(entry.id) === option.value))) {
        for (const option of [...proxy.options]) {
          if (option.value && option.value !== proxy.value && !proxies.some((entry) => String(entry.id) === option.value)) option.remove();
        }
      }
    });
    id('SyncModels').addEventListener('click', syncCatalog);

    function setDependentFields() {
      id('PassthroughModelFilter').disabled = !checked('Passthrough');
      id('CodexAllowAppServer').disabled = !checked('CodexOnly');
    }
    id('Passthrough').addEventListener('change', setDependentFields);
    id('CodexOnly').addEventListener('change', setDependentFields);

    function savePreset() {
      if (!presetKey || !rememberPreset.checked) return;
      const concurrency = id('Concurrency').valueAsNumber;
      const priority = id('Priority').valueAsNumber;
      const workspaceId = text('WorkspaceId');
      if (!id('Concurrency').checkValidity() || !Number.isInteger(concurrency) ||
          !id('Priority').checkValidity() || !Number.isInteger(priority) || !isWorkspaceId(workspaceId) ||
          [...selectedGroups].some((value) => !groups.some((group) => group.id === value))) {
        presetStatus.textContent = '修正当前设置后可更新预设。';
        return;
      }
      try {
        localStorage.setItem(presetKey, JSON.stringify({
          groupIds: [...selectedGroups], concurrency, priority, businessOnly: checked('BusinessOnly'), workspaceId,
          codexFingerprintMode: text('CodexFingerprintMode'), planTypeOverride: text('PlanTypeOverride'),
        }));
        presetStatus.textContent = '已保存此站点预设。';
      } catch {
        presetStatus.textContent = '浏览器无法保存本机预设。';
      }
    }

    function applyMatchingPreset() {
      const matches = groups.filter((group) => group.name.replace(/\s+/gu, '').toLowerCase() === 'gpt不降智分组');
      if (matches.length !== 1) return;
      selectedGroups.add(matches[0].id);
      id('Concurrency').value = '100';
      id('Priority').value = '1';
      renderGroups();
      presetStatus.textContent = '已套用 gpt 不降智分组、并发 100 和优先级 1，可直接修改。';
    }

    async function loadPreset(baseUrl) {
      try {
        const origin = new URL(baseUrl).origin;
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(origin));
        const siteHash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
        if (!hasCatalog) return;
        presetKey = `chatgpt2fa.relay.preset.v1.${siteHash}`;
        const stored = localStorage.getItem(presetKey);
        rememberPreset.disabled = false;
        if (stored === null) {
          applyMatchingPreset();
          return;
        }
        const value = JSON.parse(stored);
        if (!value || typeof value !== 'object') return;
        rememberPreset.checked = true;
        if (Array.isArray(value.groupIds)) {
          for (const groupId of value.groupIds) {
            if (isId(groupId)) selectedGroups.add(groupId);
          }
        }
        for (const [field, number] of [['Concurrency', value.concurrency], ['Priority', value.priority]]) {
          const input = id(field);
          if (Number.isInteger(number) && number >= Number(input.min) && number <= Number(input.max)) input.value = String(number);
        }
        if (typeof value.businessOnly === 'boolean') id('BusinessOnly').checked = value.businessOnly;
        if (isWorkspaceId(value.workspaceId)) id('WorkspaceId').value = value.workspaceId;
        id('CodexFingerprintMode').value = optionExists('CodexFingerprintMode', value.codexFingerprintMode) ? value.codexFingerprintMode : 'off';
        id('PlanTypeOverride').value = optionExists('PlanTypeOverride', value.planTypeOverride) ? value.planTypeOverride : '';
        renderGroups();
        presetStatus.textContent = '已读取此站点的本机预设。';
      } catch {
        rememberPreset.disabled = true;
        presetStatus.textContent = '浏览器无法读取本机预设。';
      }
    }

    rememberPreset.addEventListener('change', () => {
      if (rememberPreset.checked) {
        savePreset();
        return;
      }
      try {
        if (presetKey) localStorage.removeItem(presetKey);
        presetStatus.textContent = '已清除此站点的本机预设。';
      } catch {
        presetStatus.textContent = '浏览器未能清除本机预设。';
      }
    });
    for (const field of ['Concurrency', 'Priority', 'BusinessOnly', 'WorkspaceId', 'CodexFingerprintMode', 'PlanTypeOverride']) id(field).addEventListener('change', savePreset);

    function renderWhitelist() {
      const chips = [...whitelist].map((value) => {
        const chip = document.createElement('span');
        chip.className = 'relay-chip';
        const label = document.createElement('span');
        label.textContent = value;
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.textContent = '×';
        remove.setAttribute('aria-label', `移除 ${value}`);
        remove.addEventListener('click', () => {
          whitelist.delete(value);
          renderWhitelist();
          whitelistInput.focus();
        });
        chip.append(label, remove);
        return chip;
      });
      whitelistChipList.replaceChildren(...chips);
      whitelistClear.disabled = !whitelist.size;
    }

    function addWhitelist(keepFocus = true) {
      const value = whitelistInput.value.trim();
      if (!isModel(value)) {
        whitelistMessage.textContent = '请输入有效的模型 ID。';
        if (keepFocus) whitelistInput.focus();
        return false;
      }
      if (whitelist.size >= maxModels && !whitelist.has(value)) {
        whitelistMessage.textContent = `最多只能设置 ${maxModels} 个模型。`;
        return false;
      }
      whitelist.add(value);
      whitelistInput.value = '';
      whitelistMessage.textContent = '';
      renderWhitelist();
      if (keepFocus) whitelistInput.focus();
      return true;
    }

    id('WhitelistAdd').addEventListener('click', () => addWhitelist());
    whitelistInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.isComposing) {
        event.preventDefault();
        addWhitelist();
      }
    });
    whitelistClear.addEventListener('click', () => {
      whitelist.clear();
      whitelistInput.value = '';
      whitelistMessage.textContent = '';
      renderWhitelist();
      whitelistInput.focus();
    });

    function addMapping(container, kind, focus = true) {
      if (container.children.length >= maxModels) return;
      const {row, firstInput} = modelRow(kind);
      container.append(row);
      if (focus) firstInput.focus();
    }

    for (const [prefix, container, label] of [['Model', modelMappings, '模型'], ['Compact', compactMappings, 'Compact ']]) {
      const add = id(`${prefix}MappingAdd`);
      add.addEventListener('click', () => addMapping(container, label));
      id(`${prefix}MappingClear`).addEventListener('click', () => {
        container.replaceChildren();
        add.focus();
      });
    }

    function addTempRule() {
      if (tempRules.children.length >= 50) return;
      const row = document.createElement('div');
      row.className = 'relay-fields relay-rule-row';
      const specs = [
        {name: '状态码', type: 'number', min: '100', max: '599', placeholder: '例如 429'},
        {name: '暂停分钟', type: 'number', min: '1', max: String(maxInteger), placeholder: '例如 10'},
        {name: '关键词', type: 'text', maxLength: 1024, placeholder: '多个词用逗号分开'},
        {name: '备注（选填）', type: 'text', maxLength: 512, placeholder: '方便辨认规则'},
      ];
      for (const {name, ...spec} of specs) {
        const label = document.createElement('label');
        const caption = document.createElement('span');
        caption.className = 'field-label';
        caption.textContent = name;
        const input = Object.assign(document.createElement('input'), spec);
        input.autocomplete = 'off';
        label.append(caption, input);
        row.append(label);
      }
      const scopeLabel = document.createElement('label');
      const scopeCaption = document.createElement('span');
      scopeCaption.className = 'field-label';
      scopeCaption.textContent = '暂停范围';
      const scope = document.createElement('select');
      scope.append(new Option('当前模型', 'model'), new Option('整个账号', 'account'));
      scopeLabel.append(scopeCaption, scope);
      row.append(scopeLabel);
      const remove = document.createElement('button');
      remove.textContent = '删除';
      remove.type = 'button';
      remove.className = 'text-button';
      remove.addEventListener('click', () => row.remove());
      row.append(remove);
      tempRules.append(row);
      row.querySelector('input').focus();
    }
    id('TempRuleAdd').addEventListener('click', addTempRule);
    id('TempRuleClear').addEventListener('click', () => {
      tempRules.replaceChildren();
      id('TempRuleAdd').focus();
    });

    id('ExpiryPresets').addEventListener('click', (event) => {
      const days = Number(event.target.closest('button')?.dataset.days);
      if (!Number.isInteger(days)) return;
      if (!days) {
        expiresInput.value = '';
        return;
      }
      const value = new Date();
      value.setDate(value.getDate() + days);
      value.setMinutes(value.getMinutes() - value.getTimezoneOffset());
      expiresInput.value = value.toISOString().slice(0, 16);
    });

    const text = (suffix) => id(suffix).value.trim();
    const checked = (suffix) => id(suffix).checked;
    function clear() {
      groups = [];
      proxies = [];
      defaultGroup = null;
      modelIds = [];
      hasCatalog = false;
      presetKey = '';
      presetStatus.textContent = '';
      selectedGroups.clear();
      whitelist.clear();
      for (const input of fields.querySelectorAll('input, textarea')) {
        if (input.type === 'checkbox') input.checked = input.defaultChecked;
        else input.value = input.defaultValue;
      }
      for (const select of fields.querySelectorAll('select')) select.selectedIndex = 0;
      proxy.replaceChildren(new Option('不使用代理', ''));
      id('ProxyHint').textContent = '';
      id('ModelNotice').textContent = '';
      id('ModelCatalog').replaceChildren();
      whitelistMessage.textContent = '';
      modelMappings.replaceChildren();
      compactMappings.replaceChildren();
      tempRules.replaceChildren();
      rememberPreset.disabled = false;
      renderWhitelist();
      setModelMode();
      setDependentFields();
      setAccountOptionsCapability(accountOptionsSupported);
      renderGroups();
    }

    function read(showProblem) {
      const fail = (message, input) => {
        for (let panel = input.closest('details'); panel; panel = panel.parentElement.closest('details')) panel.open = true;
        input.focus();
        showProblem(message);
        return null;
      };
      const numbers = {};
      const codex_fingerprint_mode = text('CodexFingerprintMode');
      const plan_type_override = text('PlanTypeOverride');
      if (!optionExists('CodexFingerprintMode', codex_fingerprint_mode) || !optionExists('PlanTypeOverride', plan_type_override)) {
        return fail('请选择有效的指纹收敛模式和订阅档位。', id('CodexFingerprintMode'));
      }
      if (!accountOptionsSupported && (codex_fingerprint_mode !== 'off' || plan_type_override)) {
        return fail('当前后台尚未加载指纹收敛和订阅档位设置，请重新启动本机工具后继续。', id('CodexFingerprintMode'));
      }
      for (const [name, suffix, label] of [
        ['concurrency', 'Concurrency', '并发'], ['priority', 'Priority', '优先级'],
        ['load_factor', 'LoadFactor', '负载权重'], ['rate_multiplier', 'RateMultiplier', '计费倍率'],
      ]) {
        const input = id(suffix);
        if (name === 'load_factor' && !input.value && !input.validity.badInput) {
          numbers[name] = null;
          continue;
        }
        const value = input.valueAsNumber;
        if (!input.checkValidity() || !Number.isFinite(value)) {
          const max = input.max || maxInteger;
          return fail(name === 'rate_multiplier' ? '请输入有效的非负计费倍率。' : `${label}请输入 ${input.min} 到 ${max} 之间的整数。`, input);
        }
        numbers[name] = value;
      }
      const group_ids = [...selectedGroups];
      if (group_ids.some((value) => !groups.some((group) => group.id === value))) {
        return fail('部分选择的分组已经不可用，请重新选择。', groupSearch);
      }
      const proxy_id = proxy.value ? Number(proxy.value) : null;
      if (proxy_id !== null && !proxies.some((entry) => entry.id === proxy_id)) return fail('所选代理已经不可用，请重新选择。', proxy);
      const expires_at = expiresInput.value ? Math.trunc(new Date(expiresInput.value).getTime() / 1000) : null;
      if (expiresInput.validity.badInput || (expires_at !== null && (!Number.isSafeInteger(expires_at) || expires_at > 253402300799 || expires_at * 1000 <= Date.now()))) {
        return fail('请选择晚于现在的过期时间，或点“不过期”。', expiresInput);
      }
      const expected_workspace_id = text('WorkspaceId');
      if (!isWorkspaceId(expected_workspace_id)) return fail('工作空间 ID 应以字母或数字开头，可包含小数点、短横线和下划线。', id('WorkspaceId'));
      const upstream_request_id_header = text('UpstreamId');
      if (upstream_request_id_header && !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(upstream_request_id_header)) {
        return fail('请输入有效的响应头名称，例如 x-request-id。', id('UpstreamId'));
      }
      const model_mode = modelMode.value;
      if (model_mode === 'whitelist' && whitelistInput.value.trim() && !addWhitelist(false)) {
        return fail(whitelistMessage.textContent, whitelistInput);
      }
      if (model_mode === 'whitelist' && !whitelist.size) return fail('请添加白名单模型，或把模型策略改为“不限制”。', whitelistInput);
      const entries = (container, label) => {
        const map = new Map();
        for (const row of container.children) {
          const [from, to] = row.querySelectorAll('input');
          const source = from.value.trim();
          const target = to.value.trim();
          if (!source && !target) continue;
          if (!isModel(source, true) || !isModel(target)) {
            return fail(`${label}需要填写有效的请求模型和上游模型。通配符只能放在请求模型末尾。`, !isModel(source, true) ? from : to);
          }
          if (map.has(source)) return fail(`${label}的请求模型有重复，请删除其中一项。`, from);
          map.set(source, target);
        }
        return Object.fromEntries(map);
      };
      const model_mapping = model_mode === 'mapping' ? entries(modelMappings, '模型映射') : {};
      if (model_mapping === null) return null;
      if (model_mode === 'mapping' && !Object.keys(model_mapping).length) {
        return fail('请添加模型映射，或把模型策略改为“不限制”。', id('ModelMappingAdd'));
      }
      if (checked('Passthrough') && !checked('PassthroughModelFilter') && model_mode !== 'unrestricted') {
        return fail('请勾选“透传时仍使用模型规则”，或将模型策略改为“不限制”。', id('PassthroughModelFilter'));
      }
      const compact_model_mapping = entries(compactMappings, 'Compact 映射');
      if (compact_model_mapping === null) return null;
      const image_sizes = id('ImageSizes');
      const image_size_tiers = [...image_sizes.querySelectorAll('input:checked')].map((input) => input.value);
      if (!image_size_tiers.length) return fail('请至少选择一个图片尺寸。', image_sizes.querySelector('input'));
      const temp_unschedulable_rules = [];
      for (const row of tempRules.children) {
        const [code, duration, words, description] = row.querySelectorAll('input');
        if (![code, duration, words, description].some((input) => input.value || input.validity.badInput)) continue;
        if (!code.checkValidity() || !Number.isInteger(code.valueAsNumber)) return fail('调度规则的状态码应为 100 到 599。', code);
        if (!duration.checkValidity() || !Number.isInteger(duration.valueAsNumber)) return fail('调度规则的暂停时间应为 1 到 2147483647 分钟。', duration);
        const keywords = [...new Set(words.value.split(/[,，]/u).map((word) => word.trim()).filter(Boolean))];
        if (!keywords.length || keywords.length > 50 || keywords.some((word) => word.length > 256)) {
          return fail('每条调度规则可填写 1 至 50 个关键词，每个最多 256 个字符。', words);
        }
        temp_unschedulable_rules.push({
          error_code: code.valueAsNumber, duration_minutes: duration.valueAsNumber, keywords,
          description: description.value.trim(), scope: row.querySelector('select').value,
        });
      }
      const settings = {
        ...(accountOptionsSupported ? {codex_fingerprint_mode, plan_type_override} : {}),
        notes: text('Notes'),
        group_ids,
        proxy_id,
        upstream_request_id_header,
        ...numbers,
        expires_at,
        auto_pause_on_expired: checked('AutoPause'),
        workspace_policy: checked('BusinessOnly') ? 'business' : 'any',
        expected_workspace_id,
        model_mode,
        allowed_models: model_mode === 'whitelist' ? [...whitelist] : [],
        model_mapping,
        passthrough: checked('Passthrough'),
        passthrough_model_filter: checked('Passthrough') && checked('PassthroughModelFilter'),
        flatten_namespaces: checked('ToolCompatibility'),
        ws_mode: text('WebSocketMode'),
        long_context_billing: checked('LongContext'),
        codex_cli_only: checked('CodexOnly'),
        codex_cli_only_allow_app_server: checked('CodexOnly') && checked('CodexAllowAppServer'),
        compact_mode: text('CompactMode'),
        compact_model_mapping,
        image_size_tiers,
        temp_unschedulable_rules,
      };
      const names = (group_ids.length ? groups.filter((group) => selectedGroups.has(group.id)) : defaultGroup ? [defaultGroup] : []).map((group) => group.name);
      const selectedProxy = proxies.find((entry) => entry.id === proxy_id);
      const summary = [names.length ? `分组 ${names.join('、')}` : '不加入分组',
        selectedProxy ? `代理 ${selectedProxy.name}（ID ${selectedProxy.id}）` : '不使用代理',
        `并发 ${numbers.concurrency}`, `优先级 ${numbers.priority}`, `计费倍率 ${numbers.rate_multiplier}`,
        ...(accountOptionsSupported ? [`指纹收敛 ${id('CodexFingerprintMode').selectedOptions[0].textContent}`,
          `订阅档位 ${id('PlanTypeOverride').selectedOptions[0].textContent}`] : [])].join(' · ');
      return {settings, summary};
    }

    setDependentFields();
    return {clear, loadPreset, read, savePreset, setCatalog, setAccountOptionsCapability,
      setEnabled: (enabled) => { fields.disabled = !enabled; }};
  };
})();
