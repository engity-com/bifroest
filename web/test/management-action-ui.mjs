import assert from 'node:assert/strict';

export async function exerciseManagementActions(page, login, logout) {
  let commits=0;
  page.on('request',request=>{if(request.url().endsWith('/management/sessions/confirm'))commits++;});
  await login(page,false);
  async function connection() {
    return page.evaluate(async()=>{
      const {BrowserClient}=await import('/_bifroest/test/client.js');
      window.managementTargetAccess??=await new BrowserClient({origin:location.origin,slug:'Worker'}).password('bob','correct');
      window.managementTargetSockets??=[];
      const socket=new WebSocket(location.origin.replace('https:','wss:')+'/_bifroest/api/v1/terminal','bifroest-terminal.v1');socket.binaryType='arraybuffer';
      const index=window.managementTargetSockets.push(socket)-1;
      await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('target did not run')),5000);socket.onerror=()=>reject(new Error('target socket failed'));socket.onopen=()=>socket.send(JSON.stringify({type:'open',slug:'Worker',accessToken:window.managementTargetAccess.terminalToken(),task:'exec',command:'fixture-hold'}));socket.onmessage=event=>{if(event.data instanceof ArrayBuffer&&new TextDecoder().decode(new Uint8Array(event.data).subarray(1)).includes('management-target-live')){clearTimeout(timer);resolve();}};});
      return index;
    });
  }
  await connection();await connection();
  const table=page.getByRole('table',{name:'Live session metadata',exact:true});
  async function target() {
    await page.getByRole('button',{name:'Load sessions',exact:true}).click();
    const row=table.locator('tbody tr').filter({has:page.getByText('bob',{exact:true})});await row.waitFor();
    const id=await row.locator('td').first().textContent();await row.getByRole('button',{name:/^Session details /}).click();await page.getByRole('region',{name:'Session details',exact:true}).waitFor();return `worker/${id}`;
  }
  const id=await target();
  await page.getByRole('button',{name:'Dispose session',exact:true}).click();
  let dialog=page.getByRole('dialog');await dialog.getByText(id,{exact:true}).waitFor();
  await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
  assert.equal(await page.evaluate(()=>window.managementTargetSockets.filter(socket=>socket.readyState===WebSocket.OPEN).length),2);
  assert.equal(commits,0);
  await page.getByRole('button',{name:'Disconnect session connections',exact:true}).click();
  dialog=page.getByRole('dialog');await dialog.getByText(id,{exact:true}).waitFor();
  const confirm=dialog.getByRole('button',{name:'Confirm session action',exact:true});assert.equal(await confirm.isEnabled(),false);
  await dialog.getByLabel('Type the exact flow/session ID shown above',{exact:true}).fill('wrong-target');assert.equal(await confirm.isEnabled(),false);
  await dialog.getByLabel('Type the exact flow/session ID shown above',{exact:true}).fill(id);await confirm.click();
  await page.getByText('The server confirmed this session action and its configured audit/recording lifecycle.',{exact:false}).waitFor();
  await page.waitForFunction(()=>window.managementTargetSockets.every(socket=>socket.readyState===WebSocket.CLOSED));
  await connection(); // Explicit new execution on the same retained target grant.
  assert.equal(await target(),id,'disconnect must preserve the same persistent session');
  await page.evaluate(async()=>{const response=await fetch('/_bifroest/test/interrupt-management-confirm',{method:'POST',credentials:'omit',mode:'same-origin'});if(response.status!==204)throw new Error('fixture not armed');});
  await page.getByRole('button',{name:'Dispose session',exact:true}).click();
  dialog=page.getByRole('dialog');await dialog.getByLabel('Type the exact flow/session ID shown above',{exact:true}).fill(id);await dialog.getByRole('button',{name:'Confirm session action',exact:true}).click();
  await page.getByText('The session action result is unknown.',{exact:false}).waitFor();
  await page.waitForFunction(()=>window.managementTargetSockets.every(socket=>socket.readyState===WebSocket.CLOSED));
  assert.equal(await page.getByRole('button',{name:'Log out',exact:true}).isEnabled(),false);
  assert.equal(await page.getByRole('button',{name:'Sign in again for new connections',exact:true}).isEnabled(),false);
  await page.waitForTimeout(1300);assert.equal(commits,2,'no automatic confirmation replay after a lost response');
  await page.getByRole('combobox',{name:'Session state',exact:true}).click();await page.getByRole('option',{name:'all',exact:true}).click();
  await page.getByRole('button',{name:'Load sessions',exact:true}).click();
  await table.locator('tbody tr').filter({has:page.getByText('bob',{exact:true})}).getByText('disposed',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Dismiss local warning (does not confirm result)',exact:true}).click();
  await logout(page);
  assert.deepEqual(await page.evaluate(()=>window.cspViolations),[]);assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
}
