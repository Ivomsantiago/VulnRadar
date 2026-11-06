import {test,expect} from '@playwright/test';
test('dashboard, feed filters, navigation, watchlist persistence and export',async({page})=>{
 await page.goto('/');
 await expect(page.getByRole('heading',{name:'Visão geral',exact:true})).toBeVisible();
 await expect(page.getByText('Eventos conectados')).toBeVisible();
 await page.screenshot({path:'../docs/screenshots/dashboard.png',fullPage:true});
 await page.getByRole('link',{name:'Vulnerabilidades',exact:true}).click();
 await page.getByLabel('Filtrar severidade').selectOption('CRITICAL');
 await expect(page).toHaveURL(/severity=CRITICAL/);
 await page.getByLabel('Pesquisar vulnerabilidades').fill('CVE-');
 await expect(page).toHaveURL(/q=CVE-/);
 await page.screenshot({path:'../docs/screenshots/feed.png',fullPage:true});
 await page.getByRole('link',{name:'Watchlist',exact:true}).click();
 await page.getByRole('button',{name:'Adicionar pacote'}).click();
 await page.getByLabel('Pacote',{exact:true}).fill('vulnradar-e2e-fixture');
 await page.getByLabel('Versão opcional').fill('1.0.0');
 await page.getByRole('button',{name:'Salvar',exact:true}).click();
 await expect(page.getByText('vulnradar-e2e-fixture',{exact:true})).toBeVisible();
 await page.reload();
 await expect(page.getByText('vulnradar-e2e-fixture',{exact:true})).toBeVisible();
 await page.screenshot({path:'../docs/screenshots/watchlist.png',fullPage:true});
 await page.getByRole('button',{name:'Remover vulnradar-e2e-fixture'}).click();
 await expect(page.getByText('vulnradar-e2e-fixture',{exact:true})).toHaveCount(0);
 await page.getByRole('link',{name:'Busca universal',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Busca de pacotes e versões'})).toBeVisible();
 await page.screenshot({path:'../docs/screenshots/search.png',fullPage:true});
 await page.getByRole('link',{name:'Repositórios e análises',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Projetos autorizados'})).toBeVisible();
 await page.screenshot({path:'../docs/screenshots/projects.png',fullPage:true});
 const response=await page.request.get('/api/export?format=json');
 expect(response.status()).toBe(200);
 expect(Array.isArray(await response.json())).toBeTruthy();
});

test('advisory details, evidence and triage with isolated browser mocks',async({page})=>{
 const item={id:'CVE-2099-FIXTURE',title:'Fixture de teste isolada',description:'Dados simulados apenas neste teste.',severity:'HIGH',cvss:8.0,epss:0.01,kev:false,published:'2099-01-01',triage:'new'};
 await page.route('**/api/vulnerabilities**',async route=>{
  const url=new URL(route.request().url());
  if(route.request().method()==='PATCH'){await route.fulfill({json:{...item,triage:'investigating'}});return}
  if(url.pathname==='/api/vulnerabilities'){await route.fulfill({json:{items:[item],total:1,page:1,page_size:25}});return}
  await route.fulfill({json:{vulnerability:item,priority:{classification:'Monitoramento',reasons:['Fixture de teste']},aliases:[item.id],advisories:[],history:[],evidence:[{source:'osv',packages:[{ecosystem:'npm',package:'fixture-only',ranges:[],fixed:[]}],references:[{url:'https://osv.dev'}]}]}})
 });
 await page.goto('/feed');
 await page.getByRole('button',{name:item.id}).click();
 await expect(page.getByRole('dialog')).toBeVisible();
 await expect(page.getByText('fixture-only',{exact:true})).toBeVisible();
 await expect(page.getByText('Versões corrigidas: Não informadas pela fonte')).toBeVisible();
 await page.getByLabel('Justificativa').fill('Justificativa somente de teste');
 await page.getByRole('button',{name:'Salvar triagem'}).click();
 await expect(page.getByRole('status')).toHaveText('Triagem registrada.');
 await page.keyboard.press('Escape');
 await expect(page.getByRole('dialog')).toHaveCount(0);
});
