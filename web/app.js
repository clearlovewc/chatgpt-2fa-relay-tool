(() => {
  'use strict';
  const byId = (id) => document.getElementById(id);
  const ids = ['workspaceNav','historyNav','relayNav','workspaceView','historyView','relayView','breadcrumbCurrent','sidebarNoteTitle','sidebarNoteText','footerNote','connectionStatus','connectionText','connectionNotice','connectionNoticeText','reconnectButton','refreshButton','accountForm','accountInput','accountCount','toggleInput','systemProxy','browserLogin','skipHistoryConfirmation','preferenceStatus','formError','startButton','startButtonText','batchBadge','batchSummary','countTotal','countSuccess','countPending','countError','progressIndicator','progressMessage','resumeBox','resumeButton','batchTableWrap','batchRows','confirmationBox','confirmationCount','confirmationHint','selectAllPending','confirmationList','confirmButton','skipButton','logSection','logAccount','followButton','logViewport','emptyLogs','eventLog','resultBadge','resultEmpty','resultContent','resultSummary','resultInput','toggleResult','resultContext','copyButton','downloadButton','batchResultsButton','lastResultButton','historyFilterForm','historySearch','historyStatus','historyMessage','historyRows','historyPageInfo','historyPrev','historyNext','refreshHistoryButton','recordDialog','recordDialogMeta','closeDialogButton','historyResultInput','toggleHistoryResult','copyHistoryResult','downloadHistoryResult','toast'];
  ids.push('logoutOtherSessions','sessionCleanupHint');
  const ui = Object.fromEntries(ids.map(id => [id, byId(id)]));
  const state = { token:'', ready:false, connected:false, batch:null, submitting:false, actionPending:false, settingSaving:false, savedPreference:false, hasLast:false, resultLoading:false, result:'', historyResult:'', selectedPending:new Set(), selectedRecord:null, followActive:true, tableSignature:'', pendingSignature:'', logSignature:'', view:'workspace', pollTimer:null, polling:false, booting:false, uncertain:null, uncertainChecks:0, historyLoading:false, historyOffset:0, historyLimit:30, historyTotal:0, historyRequest:0, toastTimer:null };
  state.cleanupSupported=false;
  const statuses = {queued:'排队中',running:'处理中',waiting_confirmation:'待确认',success:'成功',error:'未完成',skipped:'已跳过',interrupted:'已中断'};
  const stageLabels = {initialized:'尚未修改',change_started:'修改状态待确认',old_disabled:'旧密钥已关闭',enrolled:'新密钥已保存',activated:'已激活，待验证',sessions_pending:'新密钥已验证，会话待清理',verified:'新密钥验证通过'};
  class ApiError extends Error { constructor(message,status=0,outcome,accountId){super(message);this.status=status;this.outcome=outcome;this.accountId=accountId;} }
  const text = (node,value) => { const next=String(value??'');if(node.textContent!==next)node.textContent=next; };
  const activeBatch = () => Boolean(state.batch && state.batch.status!=='completed');
  const batchNeedsCleanupUpgrade = () => activeBatch() && state.batch.logout_other_sessions===true && !state.cleanupSupported;
  const working = () => state.submitting || state.actionPending || Boolean(state.uncertain);
  const ready = () => state.ready && state.connected && Boolean(state.token);
  const pendingItems = () => (state.batch?.items||[]).filter(item=>item.status==='waiting_confirmation');
  const canConfirm = () => state.batch?.status==='waiting_confirmation' && !(state.batch.counts?.queued||state.batch.counts?.running||state.batch.counts?.interrupted);
  const timeValue = value => typeof value==='number' ? new Date(value>1e12?value:value*1000) : new Date(value);
  const dateText = value => { if(!value)return '—'; const date=timeValue(value);return Number.isNaN(date.getTime())?'—':date.toLocaleString('zh-CN',{hour12:false}); };
  const clockText = value => { const date=timeValue(value);return Number.isNaN(date.getTime())?'':date.toLocaleTimeString('zh-CN',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'}); };
  function toast(message){clearTimeout(state.toastTimer);text(ui.toast,message);ui.toast.hidden=false;state.toastTimer=setTimeout(()=>{ui.toast.hidden=true;},4200);}
  function formError(message=''){text(ui.formError,message);ui.formError.hidden=!message;ui.accountInput.setAttribute('aria-invalid',message?'true':'false');}
  function connection(online,message=''){
    state.connected=online;ui.connectionStatus.className=`connection-status ${online?'online':'offline'}`;text(ui.connectionText,online?'已连接本机':'连接中断');
    if(online&&!state.uncertain)ui.connectionNotice.hidden=true;
    if(!online){ui.connectionNotice.hidden=false;text(ui.connectionNoticeText,message||'暂时无法连接本机服务，已开始的任务可能仍在继续。');ui.reconnectButton.hidden=false;ui.refreshButton.hidden=true;}
    controls();
  }
  function controls(){
    relayView?.setOnline(ready());
    const blocked=!ready()||working()||state.settingSaving;
    ui.logoutOtherSessions.disabled=blocked||activeBatch()||!state.cleanupSupported;
    const cleanupUpgrade = batchNeedsCleanupUpgrade();
    const upgradeHint = cleanupUpgrade
      ? '本批次包含会话清理。请重启本机工具并刷新网页，再继续。'
      : '请重启本机工具并刷新网页，以加载按地点清理会话的功能。当前可以正常更换 2FA。';
    text(ui.sessionCleanupHint, state.cleanupSupported
      ? '默认关闭。开启后，新 2FA 验证通过才按活动会话显示的城市／地区保留同地点会话，退出其他地点。此选择随批次保存。'
      : upgradeHint);
    ui.startButton.disabled=blocked||activeBatch()||state.resultLoading;
    ui.startButton.classList.toggle('is-loading',state.submitting||Boolean(state.uncertain));
    text(ui.startButtonText,state.uncertain?'正在确认请求':state.submitting?'正在提交':state.batch?.status==='waiting_confirmation'?'请先处理待确认账号':state.batch?.status==='interrupted'?'请先继续未完成批次':state.batch?.status==='running'?'当前批次处理中':'开始批量更换');
    ui.accountInput.disabled=blocked||activeBatch();ui.toggleInput.disabled=blocked||activeBatch();ui.systemProxy.disabled=blocked||activeBatch();ui.browserLogin.disabled=blocked||activeBatch();
    ui.skipHistoryConfirmation.disabled=!ready()||state.settingSaving||state.submitting||state.actionPending||Boolean(state.uncertain);
    const selected=state.selectedPending.size;
    ui.confirmButton.disabled=blocked||cleanupUpgrade||!canConfirm()||!selected;ui.skipButton.disabled=blocked||!canConfirm()||!selected;
    ui.selectAllPending.disabled=blocked||!canConfirm();
    ui.confirmationList.querySelectorAll('input').forEach(input=>{input.disabled=blocked||!canConfirm();input.checked=state.selectedPending.has(input.dataset.recordId);});
    ui.resumeButton.disabled=blocked||cleanupUpgrade||state.batch?.status!=='interrupted';
    ui.batchResultsButton.disabled=!ready()||working()||state.resultLoading||!(state.batch?.counts?.success>0);
    ui.lastResultButton.disabled=!ready()||working()||state.resultLoading||!state.hasLast;
    ui.copyButton.disabled=!state.result;ui.downloadButton.disabled=!state.result;
    ui.historyPrev.disabled=!ready()||state.historyLoading||state.historyOffset<=0;
    ui.historyNext.disabled=!ready()||state.historyLoading||state.historyOffset+state.historyLimit>=state.historyTotal;
    ui.refreshHistoryButton.disabled=!ready()||state.historyLoading;
    document.querySelectorAll('[data-result-id]').forEach(button=>{button.disabled=!ready()||state.resultLoading;});
  }
  async function request(path,{method='GET',body,bootstrap=false,timeout=15000}={}){
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeout);
    try{
      const headers={Accept:'application/json'};if(!bootstrap&&state.token)headers['X-Local-Token']=state.token;if(body!==undefined)headers['Content-Type']='application/json';
      const response=await fetch(path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',mode:'same-origin',cache:'no-store',signal:controller.signal});
      let data;try{data=await response.json();}catch{throw new ApiError('响应暂时无法确认，请重新连接查看任务状态。',response.ok?0:response.status);}
      if(!response.ok)throw new ApiError(typeof data?.detail==='string'?data.detail:'当前操作未完成，请稍后再试。',response.status,data?.outcome,data?.account_id);
      return data;
    }catch(error){if(error instanceof ApiError)throw error;throw new ApiError('暂时无法连接本机工具。');}finally{clearTimeout(timer);}
  }
  function toggleMask(field,button,label){const visible=field.classList.contains('secret-masked');field.classList.toggle('secret-masked',!visible);button.setAttribute('aria-pressed',String(visible));button.setAttribute('aria-label',`${visible?'隐藏':'显示'}${label}`);}
  function resetMask(field,button,label){field.classList.add('secret-masked');button.setAttribute('aria-pressed','false');button.setAttribute('aria-label',`显示${label}`);}
  function clearResult(){state.result='';ui.resultInput.value='';resetMask(ui.resultInput,ui.toggleResult,'完整结果');ui.resultContent.hidden=true;ui.resultEmpty.hidden=false;ui.resultBadge.hidden=true;controls();}
  function showResult(line,{summary='已读取成功结果',history=false,cleanupPending=false,context='结果已保存到本机历史记录。'}={}){
    if(typeof line!=='string'||!line.trim())throw new ApiError('没有可读取的成功结果。');
    state.result=line.trim();ui.resultInput.value=state.result;resetMask(ui.resultInput,ui.toggleResult,'完整结果');ui.resultEmpty.hidden=true;ui.resultContent.hidden=false;ui.resultBadge.hidden=false;ui.resultBadge.className=`badge ${history?'history':'success'}`;text(ui.resultBadge,history?'历史结果':'已验证');text(ui.resultSummary,summary);text(ui.resultContext,context);if(!cleanupPending)state.hasLast=true;if(cleanupPending){ui.resultBadge.className='badge history';text(ui.resultBadge,'会话待清理');}text(byId('resultTitle'),cleanupPending?'新密钥（会话待清理）':'成功结果');controls();
  }
  function badge(status){const node=document.createElement('span');node.className=`badge ${status==='success'?'success':status==='error'||status==='interrupted'?'error':status==='waiting_confirmation'?'history':status==='running'?'running':'neutral'}`;node.textContent=statuses[status]||'状态未知';return node;}
  function actionButton(label,callback,{resultId}={}){const button=document.createElement('button');button.type='button';button.className='text-button table-action';button.textContent=label;if(resultId)button.dataset.resultId=resultId;button.addEventListener('click',callback);return button;}
  function accountCell(record){const cell=document.createElement('td');const email=document.createElement('strong');email.className='record-email';email.textContent=record.email||'—';const detail=document.createElement('small');detail.className='record-detail';detail.textContent=record.has_history?'已有历史记录':'首次处理';cell.append(email,detail);return cell;}
  // Old history stores the original wording from before identity was checked separately.
  function progressText(message, running = false) {
    if (message === '浏览器登录已完成，正在核对账号身份。') {
      const status = '浏览器已收到登录标记，账号身份仍待核对。';
      return running ? status + ' 若 Chrome 显示介绍页，请在窗口中选择所需选项，后续页面有“跳过”时可逐页点击。' : status;
    }
    if (message === '网站要求通过浏览器完成后续登录或人工确认，当前自动登录尚未完成。') {
      return '浏览器登录未完成。这条记录没有区分普通引导和安全验证。';
    }
    return message || '';
  }
  function statusCell(record){const cell=document.createElement('td');cell.append(badge(record.status));const message=document.createElement('small');message.className='record-detail';message.textContent=progressText(record.message, record.status === 'running')||stageLabels[record.stage]||'';cell.append(message);return cell;}
  function renderBatchTable(batch){
    const items=batch?.items||[];ui.batchTableWrap.hidden=!items.length;
    const signature=JSON.stringify(items.map(item=>[item.id,item.email,item.status,item.stage,item.message,item.has_history,item.has_result,item.cleanup_pending]));
    if(signature===state.tableSignature)return;state.tableSignature=signature;
    const fragment=document.createDocumentFragment();
    for(const item of items){const row=document.createElement('tr');row.dataset.recordId=item.id;row.append(accountCell(item),statusCell(item));const actions=document.createElement('td');const wrap=document.createElement('div');wrap.className='table-actions';wrap.append(actionButton('进度',()=>{state.selectedRecord=item.id;state.followActive=false;renderLog();}));if(item.has_result)wrap.append(actionButton(item.cleanup_pending?'查看新密钥':'查看结果',()=>readRecord(item,false),{resultId:item.id}));actions.append(wrap);row.append(actions);fragment.append(row);}
    ui.batchRows.replaceChildren(fragment);
  }
  function renderConfirmation(){
    const items=pendingItems();ui.confirmationBox.hidden=!items.length;text(ui.confirmationCount,`${items.length} 个待确认`);
    text(ui.confirmationHint,canConfirm()?'确认后将使用本次输入的当前密钥，再次更换所选账号的 2FA。':'正在优先处理前面的账号，完成后即可确认这些历史账号。');
    const valid=new Set(items.map(item=>item.id));state.selectedPending=new Set([...state.selectedPending].filter(id=>valid.has(id)));
    const signature=items.map(item=>item.id).join('|');
    if(signature!==state.pendingSignature){
      const previous=new Set(state.pendingSignature?state.pendingSignature.split('|'):[]);for(const item of items)if(!previous.has(item.id))state.selectedPending.add(item.id);
      state.pendingSignature=signature;const fragment=document.createDocumentFragment();
      for(const item of items){const label=document.createElement('label');label.className='checkbox-label confirmation-item';const check=document.createElement('input');check.type='checkbox';check.dataset.recordId=item.id;check.checked=state.selectedPending.has(item.id);check.addEventListener('change',()=>{if(check.checked)state.selectedPending.add(item.id);else state.selectedPending.delete(item.id);updatePendingSelection();});const name=document.createElement('span');name.textContent=item.email||'—';label.append(check,name);fragment.append(label);}
      ui.confirmationList.replaceChildren(fragment);
    }
    updatePendingSelection();
  }
  function updatePendingSelection(){const count=pendingItems().length;ui.selectAllPending.checked=count>0&&state.selectedPending.size===count;ui.selectAllPending.indeterminate=state.selectedPending.size>0&&state.selectedPending.size<count;controls();}
  function renderLog(){
    const items=state.batch?.items||[];let item;
    if(state.followActive)item=items.find(record=>record.status==='running')||items.find(record=>record.status==='interrupted')||[...items].reverse().find(record=>record.events?.length)||items[0];
    else item=items.find(record=>record.id===state.selectedRecord)||items[0];
    ui.logSection.hidden=!item;if(!item)return;state.selectedRecord=item.id;text(ui.logAccount,`运行记录 · ${item.email||'当前账号'}`);
    const signature=JSON.stringify([item.id,item.events]);if(signature===state.logSignature)return;state.logSignature=signature;
    const nearBottom=ui.logViewport.scrollHeight-ui.logViewport.scrollTop-ui.logViewport.clientHeight<45;const fragment=document.createDocumentFragment();
    for(const event of item.events||[]){const row=document.createElement('li');const time=document.createElement('span');time.className='event-time';time.textContent=clockText(event.time);const content=document.createElement('span');content.className='event-text';content.textContent=progressText(event.text);row.append(time,content);fragment.append(row);}
    ui.eventLog.replaceChildren(fragment);ui.emptyLogs.hidden=Boolean(item.events?.length);if(nearBottom)ui.logViewport.scrollTop=ui.logViewport.scrollHeight;
  }
  function renderBatch(batch){
    const changed=(batch?.id||null)!==(state.batch?.id||null);const oldStatus=state.batch?.status;
    if(changed){clearResult();state.selectedPending.clear();state.pendingSignature='';state.tableSignature='';state.logSignature='';state.followActive=true;}
    if(batch&&batch.status!=='completed')ui.logoutOtherSessions.checked=batch.logout_other_sessions===true;
    state.batch=batch||null;const status=batch?.status||'idle';const labels={idle:'等待开始',running:'处理中',waiting_confirmation:'等待确认',completed:'本批次结束',interrupted:'已中断'};
    text(ui.batchBadge,labels[status]||'状态待确认');ui.batchBadge.className=`badge ${status==='running'?'running':status==='waiting_confirmation'?'history':status==='interrupted'?'error':status==='completed'?'success':'neutral'}`;
    ui.batchSummary.hidden=!batch;const counts=batch?.counts||{};text(ui.countTotal,counts.total||0);text(ui.countSuccess,counts.success||0);text(ui.countPending,counts.waiting_confirmation||0);text(ui.countError,(counts.error||0)+(counts.interrupted||0));
    const fallback={idle:'粘贴多条账号后，点击“开始批量更换”。',running:'正在按顺序处理账号，成功结果会逐条保存。',waiting_confirmation:'新账号已处理完，请确认是否再次更换已有记录的账号。',completed:'本批次已结束。成功结果已保存，其他账号的具体状态可在列表中查看。',interrupted:'本批次中途停止，点击继续可按保存记录处理未完成项。'};
    text(ui.progressMessage,batch?.message||fallback[status]||fallback.idle);ui.progressIndicator.className=`progress-indicator ${status==='running'?'running':status==='interrupted'?'error':status==='completed'?'success':''}`;ui.resumeBox.hidden=status!=='interrupted';
    renderBatchTable(batch);renderConfirmation();renderLog();controls();
    if(state.view==='history'&&(changed||oldStatus!==status)&&!state.historyLoading)loadHistory();
  }
  function schedulePoll(delay=1200){clearTimeout(state.pollTimer);state.pollTimer=setTimeout(poll,delay);}
  function reconcileUncertain(){
    const pending=state.uncertain;if(!pending)return;
    let resolved=false;
    if(pending.kind==='submit')resolved=Boolean(state.batch&&state.batch.id!==pending.batchId);
    else if(state.batch?.id===pending.batchId){
      if(pending.kind==='resume')resolved=state.batch.status!=='interrupted';
      else resolved=pending.ids.every(id=>{const item=state.batch.items.find(record=>record.id===id);return item&&item.status!=='waiting_confirmation';});
    }
    if(resolved){state.uncertain=null;state.uncertainChecks=0;ui.connectionNotice.hidden=true;ui.accountInput.value='';updateCount();controls();return;}
    state.uncertainChecks+=1;ui.connectionNotice.hidden=false;ui.reconnectButton.hidden=true;ui.refreshButton.hidden=state.uncertainChecks<5;text(ui.connectionNoticeText,state.uncertainChecks<5?'正在核对刚才的操作，请不要重复提交。':'尚未确认刚才的操作。请刷新页面查看保存的状态，再决定下一步。');controls();
  }
  async function poll(){
    if(state.polling||state.booting){schedulePoll();return;}if(!state.token||!state.ready){bootstrap();return;}
    state.polling=true;
    try{const data=await request('/api/batch');connection(true);renderBatch(data.batch);reconcileUncertain();}
    catch(error){connection(false,error.message);if(error.status===401||error.status===403){state.token='';state.ready=false;}}
    finally{state.polling=false;if(activeBatch()||state.uncertain||!state.connected)schedulePoll(state.connected?1200:2500);}
  }
  async function bootstrap(){
    if(state.booting)return;state.booting=true;clearTimeout(state.pollTimer);
    try{
      const data=await request('/api/bootstrap',{bootstrap:true});
      if(data.app!=='chatgpt-2fa-local-web'||data.api_version!==2){relayView?.setCapability(false);state.token='';state.ready=false;connection(false,'本地服务需要完成更新。请在服务更新后刷新页面。');ui.reconnectButton.hidden=true;ui.refreshButton.hidden=false;return;}
      if(typeof data.token!=='string'||!data.token)throw new ApiError('页面会话尚未准备好，请重新连接。');
      if(state.token&&state.token!==data.token)relayView?.resetSession();
      state.cleanupSupported=Number.isInteger(data.session_cleanup_version)&&data.session_cleanup_version>=3;if(!state.cleanupSupported)ui.logoutOtherSessions.checked=false;
      state.token=data.token;state.ready=true;relayView?.setCapability(data.relay_oauth===true,data.relay_settings_version,data.relay_login_version,data.relay_saved_sites_version,data.relay_reauth_version,data.relay_watch_version,data.relay_import_version);state.hasLast=Boolean(data.has_last_result);state.savedPreference=data.settings?.skip_history_confirmation===true;ui.skipHistoryConfirmation.checked=state.savedPreference;connection(true);renderBatch(data.batch);reconcileUncertain();if(state.view==='history')loadHistory();
    }catch(error){state.token='';state.ready=false;connection(false,error.message);}
    finally{state.booting=false;controls();if(activeBatch()||state.uncertain||!state.connected)schedulePoll(state.connected?1200:3000);}
  }
  function updateCount(){const count=ui.accountInput.value.split(/\r?\n/).filter(line=>line.trim()).length;text(ui.accountCount,`${count} 个账号`);}
  ui.accountForm.addEventListener('submit',async event=>{
    event.preventDefault();if(!ready()||working()||activeBatch()||state.settingSaving||state.resultLoading)return;
    const lines=ui.accountInput.value.trim();const accounts=lines.split(/\r?\n/).filter(line=>line.trim());
    if(!lines){formError('请粘贴至少一条账号信息。');return;}if(accounts.length>500){formError('每批最多 500 个账号，请分批处理。');return;}
    for(let index=0;index<accounts.length;index++){const line=accounts[index];if(line.length>8192||line.indexOf('----')<0||line.indexOf('----')===line.lastIndexOf('----')){formError(`第 ${index+1} 条格式不正确，请使用“邮箱----密码----当前2FA密钥”。`);return;}}
    formError();state.submitting=true;const previousId=state.batch?.id||null;controls();
    try{const data=await request('/api/batches',{method:'POST',body:{lines,use_system_proxy:ui.systemProxy.checked,browser_login:ui.browserLogin.checked,skip_history_confirmation:ui.skipHistoryConfirmation.checked,...(state.cleanupSupported?{logout_other_sessions:ui.logoutOtherSessions.checked}:{})}});if(!data.batch?.id)throw new ApiError('批次提交结果尚未确认。');ui.accountInput.value='';updateCount();renderBatch(data.batch);schedulePoll(300);}
    catch(error){if(!error.status||error.status>=500){state.uncertain={kind:'submit',batchId:previousId};state.uncertainChecks=0;connection(false,'提交结果暂未确认，正在查询已保存的批次。请不要重复提交。');schedulePoll(700);}else{formError(error.message);if(error.status===409)schedulePoll(100);if(error.status===401||error.status===403)bootstrap();}}
    finally{state.submitting=false;controls();}
  });
  async function batchAction(kind){
    if(!ready()||working()||state.settingSaving||!state.batch)return;
    if(kind!=='skip' && batchNeedsCleanupUpgrade())return;
    const batchId=state.batch.id;const ids=[...state.selectedPending];if(kind!=='resume'&&(!canConfirm()||!ids.length))return;
    state.actionPending=true;controls();
    try{const data=await request(`/api/batches/${encodeURIComponent(batchId)}/${kind}`,{method:'POST',body:kind==='resume'?{}:{record_ids:ids}});if(!data.batch?.id)throw new ApiError('操作结果尚未确认。');renderBatch(data.batch);schedulePoll(300);}
    catch(error){if(!error.status||error.status>=500){state.uncertain={kind,batchId,ids};state.uncertainChecks=0;connection(false,'操作结果暂未确认，正在查询批次状态。请不要重复操作。');schedulePoll(700);}else{toast(error.message);schedulePoll(200);}}
    finally{state.actionPending=false;controls();}
  }
  ui.confirmButton.addEventListener('click',()=>batchAction('confirm'));ui.skipButton.addEventListener('click',()=>batchAction('skip'));ui.resumeButton.addEventListener('click',()=>batchAction('resume'));
  ui.selectAllPending.addEventListener('change',()=>{state.selectedPending=ui.selectAllPending.checked?new Set(pendingItems().map(item=>item.id)):new Set();updatePendingSelection();});
  ui.skipHistoryConfirmation.addEventListener('change',async()=>{
    if(!ready()||state.settingSaving)return;state.settingSaving=true;const requested=ui.skipHistoryConfirmation.checked;text(ui.preferenceStatus,'正在保存默认选项…');controls();
    try{const data=await request('/api/settings',{method:'POST',body:{skip_history_confirmation:requested}});state.savedPreference=data.settings?.skip_history_confirmation===true;ui.skipHistoryConfirmation.checked=state.savedPreference;text(ui.preferenceStatus,'默认选项已保存。当前已等待确认的账号仍需手动确认。');}
    catch(error){ui.skipHistoryConfirmation.checked=state.savedPreference;text(ui.preferenceStatus,'默认选项暂未确认，请重新连接后查看。');toast(error.message);if(!error.status||error.status>=500){connection(false,'正在重新读取默认选项，避免使用未确认的设置。');bootstrap();}}
    finally{state.settingSaving=false;controls();}
  });
  async function readRecord(record,inHistory){
    if(!ready()||state.resultLoading||!record.has_result)return;state.resultLoading=true;controls();const batchId=state.batch?.id;
    try{const data=await request(`/api/history/${encodeURIComponent(record.id)}/result`);if(typeof data.line!=='string'||!data.line.trim())throw new ApiError('该条记录尚无可读取的成功结果。');
      if(inHistory){text(byId('recordDialogTitle'),data.cleanup_pending?'新密钥已验证，会话清理未完成':'已保存的更换记录');text(ui.recordDialog.querySelector('.dialog-note'),data.cleanup_pending?'新密钥已保存。继续原任务只会清理会话。':'这里读取的是已保存记录，不会再次修改账号。');state.historyResult=data.line.trim();ui.historyResultInput.value=state.historyResult;resetMask(ui.historyResultInput,ui.toggleHistoryResult,'历史结果');text(ui.recordDialogMeta,`${record.email} · ${dateText(record.finished_at||record.created_at)}`);if(!ui.recordDialog.open)ui.recordDialog.showModal();}
      else if(state.batch?.id===batchId)showResult(data.line,{summary:data.cleanup_pending?'新密钥已验证，会话清理尚未完成':`已读取 ${record.email} 的成功结果`,cleanupPending:data.cleanup_pending===true,context:data.cleanup_pending?'可复制新密钥。点击继续未完成批次，只继续清理会话，不再次更换 2FA。':'这是本条任务已经验证并保存的结果。读取不会再次修改账号。'});
    }catch(error){toast(error.message);}finally{state.resultLoading=false;controls();}
  }
  ui.batchResultsButton.addEventListener('click',async()=>{
    if(!ready()||state.resultLoading||!state.batch?.counts?.success)return;state.resultLoading=true;controls();const batchId=state.batch.id;
    try{const data=await request(`/api/batches/${encodeURIComponent(batchId)}/results`);if(state.batch?.id===batchId)showResult(data.line,{summary:`已读取本批 ${data.count||0} 条成功结果`,context:'仅包含已经通过新密钥登录验证的账号，每行一条。其他状态可在批次列表和历史中查看。'});}catch(error){toast(error.message);}finally{state.resultLoading=false;controls();}
  });
  ui.lastResultButton.addEventListener('click',async()=>{
    if(!ready()||state.resultLoading)return;state.resultLoading=true;controls();const batchId=state.batch?.id||null;
    try{const data=await request('/api/result/latest');if((state.batch?.id||null)===batchId)showResult(data.line,{summary:'已读取最近保存的单条结果',history:true,context:'这是之前保存的结果，本次读取不会再次修改账号。'});}catch(error){toast(error.message);}finally{state.resultLoading=false;controls();}
  });
  function renderHistory(records){
    const fragment=document.createDocumentFragment();
    for(const record of records){const row=document.createElement('tr');const account=accountCell(record);account.querySelector('.record-detail').textContent=dateText(record.finished_at||record.started_at||record.created_at);const mode=document.createElement('td');mode.textContent=record.has_history?'再次处理':'首次处理';const status=statusCell(record);const actions=document.createElement('td');if(record.has_result)actions.append(actionButton(record.cleanup_pending?'查看新密钥':'查看结果',()=>readRecord(record,true),{resultId:record.id}));else{const note=document.createElement('span');note.className='record-muted';note.textContent='暂无已验证结果';actions.append(note);}if(record.has_result&&record.email)actions.append(actionButton('重授权',()=>openReauthForRecord(record)));row.append(account,mode,status,actions);fragment.append(row);}
    ui.historyRows.replaceChildren(fragment);
  }
  async function loadHistory(){
    if(!ready())return;const requestId=++state.historyRequest;state.historyLoading=true;text(ui.historyMessage,'正在读取历史记录…');controls();
    const params=new URLSearchParams({q:ui.historySearch.value.trim(),status:ui.historyStatus.value,offset:String(state.historyOffset),limit:String(state.historyLimit)});
    try{const data=await request(`/api/history?${params}`);if(requestId!==state.historyRequest)return;const records=Array.isArray(data.records)?data.records:[];state.historyTotal=Number(data.total)||0;renderHistory(records);text(ui.historyMessage,records.length?'记录保存在本机，刷新页面后仍可查询。':'当前条件下没有历史记录。');text(ui.historyPageInfo,state.historyTotal?`第 ${state.historyOffset+1}–${Math.min(state.historyOffset+records.length,state.historyTotal)} 条，共 ${state.historyTotal} 条`:'0 条记录');}
    catch(error){if(requestId===state.historyRequest){text(ui.historyMessage,error.message);renderHistory([]);}}
    finally{if(requestId===state.historyRequest){state.historyLoading=false;controls();}}
  }
  function openReauthForRecord(record){
    location.hash='#relay';
    switchView();
    relayView?.fromHistory(record);
  }
  function switchView(){
    state.view=location.hash==='#history'?'history':location.hash==='#relay'?'relay':'workspace';
    const views=[['workspace',ui.workspaceView,ui.workspaceNav,'批量更换'],['history',ui.historyView,ui.historyNav,'历史记录'],['relay',ui.relayView,ui.relayNav,'中转站上号']];
    for(const [key,panel,nav,label] of views){
      const current=state.view===key;
      panel.hidden=!current;
      nav.classList.toggle('active',current);
      if(current){nav.setAttribute('aria-current','page');text(ui.breadcrumbCurrent,label);}
      else nav.removeAttribute('aria-current');
    }
    const inRelay=state.view==='relay';
    relayView?.setVisible(inRelay);
    text(ui.sidebarNoteTitle,inRelay?'自动登录与入站':'进度与结果自动保存');
    text(ui.sidebarNoteText,inRelay?'三段账号信息用于自动登录，授权回调自动接收。':'每一次更换都有记录，刷新后也能继续查看。');
    text(ui.footerNote,inRelay?'队列仅在本页保留':'记录保存在本机，完整结果按需查看');
    if(state.view==='history')loadHistory();
  }
  ui.historyFilterForm.addEventListener('submit',event=>{event.preventDefault();state.historyOffset=0;loadHistory();});
  ui.historyStatus.addEventListener('change',()=>{state.historyOffset=0;loadHistory();});
  ui.refreshHistoryButton.addEventListener('click',()=>loadHistory());
  ui.historyPrev.addEventListener('click',()=>{state.historyOffset=Math.max(0,state.historyOffset-state.historyLimit);loadHistory();});
  ui.historyNext.addEventListener('click',()=>{if(state.historyOffset+state.historyLimit<state.historyTotal){state.historyOffset+=state.historyLimit;loadHistory();}});
  async function copy(value,field,button,label){
    if(!value)return;
    try{if(navigator.clipboard?.writeText)await navigator.clipboard.writeText(value);else{const buffer=document.createElement('textarea');buffer.className='clipboard-buffer';buffer.value=value;buffer.setAttribute('readonly','');document.body.append(buffer);buffer.select();try{if(!document.execCommand('copy'))throw new Error();}finally{buffer.remove();}}toast('已复制完整结果。');}
    catch{field.classList.remove('secret-masked');button.setAttribute('aria-pressed','true');button.setAttribute('aria-label',`隐藏${label}`);field.focus();field.select();toast('浏览器未允许自动复制，请按 Ctrl+C 复制已选中的结果。');}
  }
  function download(value,name){if(!value)return;const url=URL.createObjectURL(new Blob([value.replace(/\r?\n/g,'\r\n')+'\r\n'],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('已准备下载完整结果。');}
  ui.copyButton.addEventListener('click',()=>copy(state.result,ui.resultInput,ui.toggleResult,'完整结果'));ui.downloadButton.addEventListener('click',()=>download(state.result,'chatgpt-2fa-results.txt'));
  ui.copyHistoryResult.addEventListener('click',()=>copy(state.historyResult,ui.historyResultInput,ui.toggleHistoryResult,'历史结果'));ui.downloadHistoryResult.addEventListener('click',()=>download(state.historyResult,'chatgpt-2fa-history-result.txt'));
  ui.toggleInput.addEventListener('click',()=>toggleMask(ui.accountInput,ui.toggleInput,'账号信息'));ui.toggleResult.addEventListener('click',()=>toggleMask(ui.resultInput,ui.toggleResult,'完整结果'));ui.toggleHistoryResult.addEventListener('click',()=>toggleMask(ui.historyResultInput,ui.toggleHistoryResult,'历史结果'));
  ui.closeDialogButton.addEventListener('click',()=>ui.recordDialog.close());ui.recordDialog.addEventListener('close',()=>{state.historyResult='';ui.historyResultInput.value='';});
  ui.followButton.addEventListener('click',()=>{state.followActive=true;renderLog();});ui.accountInput.addEventListener('input',()=>{updateCount();if(!ui.formError.hidden)formError();});
  ui.reconnectButton.addEventListener('click',()=>bootstrap());ui.refreshButton.addEventListener('click',()=>location.reload());
  window.addEventListener('hashchange',switchView);window.addEventListener('online',()=>bootstrap());window.addEventListener('offline',()=>connection(false));
  document.addEventListener('visibilitychange',()=>{if(!document.hidden){if(activeBatch()||!state.connected||state.uncertain)schedulePoll(100);if(state.view==='history')loadHistory();}});
  const relayView=window.createRelayView?.({request,reconnect:bootstrap});
  switchView();updateCount();bootstrap();
})();
