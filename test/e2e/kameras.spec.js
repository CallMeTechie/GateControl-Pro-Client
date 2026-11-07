'use strict';

const fs = require('fs');
const path = require('path');
const { test, expect } = require('./support/fixtures');
const { setupWithApiKey } = require('./support/ui');

// Kameras im Heimnetz (plugin gatecontrol-door 1.6.0 "Tür & Kamera"): shown
// only while the server has the plugin with home cameras and the person sees
// one; without VPN a new still every 10 s with the hint, through the VPN the
// live video (continuous fMP4 through gccam:), "Standbild speichern",
// "Vollbild", "Ton", "Clips heute" with type pills and playback, the cameras
// as cards; a camera push carries its picture in the toast and opens the
// camera; Ring pushes stay in the inbox. Selectors by id/class.

const CAM1 = 'c0123456789abcde';
const CAM2 = 'cfedcba987654321';
const ago = (min) => new Date(Date.now() - min * 60000).toISOString();

function doorData(o = {}) {
  return {
    cameras: [
      { id: CAM1, name: 'Einfahrt', model: 'Reolink RLC-510A' },
      { id: CAM2, name: 'Garten', model: 'Tapo C320WS', settings: { record: 'away', events: [], retentionDays: 7, stream: 'sub', audio: false } },
    ],
    clips: {
      [CAM1]: [
        { id: 'e000000000000001', kind: 'person', kinds: ['person'], startedAt: ago(30), ms: 24000, nobodyHome: true },
        { id: 'e000000000000002', kind: 'vehicle', kinds: ['vehicle'], startedAt: ago(90), ms: 11000 },
        { id: 'e000000000000003', kind: 'animal', kinds: ['animal'], startedAt: ago(300), ms: 8000, noClip: true },
      ],
      [CAM2]: [],
    },
    ...o,
  };
}

const camPage = (page) => page.locator('#page-kameras');

test.describe('kameras', () => {
  test('no Tür & Kamera, an older GateControl, or no camera seen: no "Kameras" entry', async ({ launchApp, mock }) => {
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect.poll(() => mock.count('/api/v1/client/plugins')).toBeGreaterThan(0);
    await expect(page.locator('#nav-kameras')).toBeHidden();

    const door = mock.setDoor({ ...doorData(), supported: false });
    await page.locator('#nav-inbox').click();
    // the next check (push reconnect / app start) — ask the service directly through the bridge
    await page.evaluate(() => window.gatecontrol.cameras.check());
    await expect(page.locator('#nav-kameras')).toBeHidden();
    door.supported = true;
    door.cameras = [];
    await page.evaluate(() => window.gatecontrol.cameras.check());
    await expect(page.locator('#nav-kameras')).toBeHidden();
  });

  test('without VPN: stills every 10 s with the hint, chips, cards, Clips heute with pills, a clip plays', async ({ launchApp, mock }) => {
    const door = mock.setDoor(doorData());
    const { page } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-kameras')).toBeVisible();
    await page.locator('#nav-kameras').click();
    const p = camPage(page);
    await expect(p).toHaveClass(/active/);

    await expect(p.locator('.cm-chip')).toHaveCount(2);
    await expect(p.locator('.cm-chip.is-on')).toHaveText('Einfahrt');
    await expect(p.locator('.cm-title .cm-pill')).toHaveText(/2 online/);
    // the still through gccam:, the badge and the hint of the mockup
    await expect(p.locator('img.cm-media')).toBeVisible();
    await expect(p.locator('img.cm-media')).toHaveAttribute('src', /^gccam:\/\/media\/.+\/snapshot\.jpg\?t=\d+$/);
    await expect.poll(() => p.locator('img.cm-media').evaluate((img) => img.naturalWidth)).toBe(320);
    await expect(p.locator('.cm-ov-pill.is-still')).toHaveText(/(Standbild · alle|Still · every) 10 s/);
    await expect(p.locator('.cm-ov-stamp')).toHaveText(/^Einfahrt · \d{1,2}:\d{2}:\d{2}( [AP]M)?$/);
    await expect(p.locator('.cm-hint')).toContainText(/alle 10 Sekunden ein neues Standbild|a new still every 10 seconds/);
    expect(door.media).toContain('snapshot.jpg');
    // Ton only with live video
    await expect(p.locator('.cm-act').nth(2)).toBeDisabled();

    // cards: picture, Heimnetz · live, model · motion · clips
    await expect(p.locator('.cm-cam')).toHaveCount(2);
    await expect(p.locator('.cm-cam').first()).toContainText(/Heimnetz|Home network/);
    await expect(p.locator('.cm-cam').first()).toContainText(/Reolink RLC-510A · (Bewegung: Personen, Autos · Clips 14 Tage|Motion: people, cars · Clips 14 days)/);
    await expect(p.locator('.cm-cam').nth(1)).toContainText(/nur wenn niemand zu Hause|only when nobody is at home/);

    // Clips heute: newest first, pills, "nur Vorschaubild" without a clip
    const rows = p.locator('.cm-clip');
    await expect(rows).toHaveCount(3);
    await expect(rows.nth(0)).toContainText('Person · 0:24');
    await expect(rows.nth(0)).toContainText(/Niemand zu Hause|Nobody at home/);
    await expect(rows.nth(0).locator('.cm-pill.is-warn')).toHaveText('Person');
    await expect(rows.nth(1).locator('.cm-pill.is-info')).toHaveText(/^(Auto|Car)$/);
    await expect(rows.nth(2)).toContainText(/nur Vorschaubild|preview only/);
    await expect(rows.nth(2)).not.toHaveAttribute('type', 'button');

    // play a clip in the player (Range through gccam:), back to the still
    await rows.nth(0).click();
    const video = p.locator('video.cm-media');
    await expect(video).toBeVisible();
    await expect(video).toHaveAttribute('src', /^gccam:\/\/media\/.+\/clip\.mp4$/);
    await expect(p.locator('.cm-ov-pill.is-clip')).toContainText('Clip · Person');
    await expect.poll(() => video.evaluate((v) => v.readyState), { timeout: 20000 }).toBeGreaterThanOrEqual(2);
    await expect(p.locator('.cm-act').nth(2)).toBeEnabled();
    await p.locator('.cm-back').click();
    await expect(p.locator('img.cm-media')).toBeVisible();

    // the other camera: its (empty) clips
    await p.locator('.cm-chip', { hasText: 'Garten' }).click();
    await expect(p.locator('.cm-chip.is-on')).toHaveText('Garten');
    await expect(p.locator('.cm-clips')).toContainText(/Heute noch keine Clips|No clips today yet/);
    await expect.poll(() => door.log.filter((l) => l.route === `cameras/home/${CAM2}/live`).length).toBeGreaterThan(0);
  });

  test('through the VPN: live video with LIVE · HD über VPN, Ton, Standbild speichern', async ({ launchApp, mock }) => {
    const door = mock.setDoor({ ...doorData(), mode: 'live' });
    const { app, page, dir } = await launchApp();
    await setupWithApiKey(page, mock);
    await page.locator('#nav-kameras').click();
    const p = camPage(page);
    const video = p.locator('video.cm-media');
    await expect(video).toHaveAttribute('src', /^gccam:\/\/media\/.+\/live\.mp4$/);
    await expect.poll(() => video.evaluate((v) => v.readyState), { timeout: 20000 }).toBeGreaterThanOrEqual(2);
    await expect(p.locator('.cm-ov-pill.is-live')).toHaveText('● LIVE');
    await expect(p.locator('.cm-ov-pill.is-dark')).toHaveText(/^HD · (über|via) VPN$/);
    await expect(p.locator('.cm-hint')).toContainText(/Live-Video über den Tunnel|Live video through the tunnel/);
    expect(door.media).toContain('live.mp4');

    // Ton: muted until switched on
    const sound = p.locator('.cm-act').nth(2);
    await expect(sound).toBeEnabled();
    expect(await video.evaluate((v) => v.muted)).toBe(true);
    await sound.click();
    await expect(sound).toHaveAttribute('aria-pressed', 'true');
    expect(await video.evaluate((v) => v.muted)).toBe(false);

    // Standbild speichern → Pictures, "<camera> <date> <time>.jpg"
    const out = path.join(dir, 'bilder', 'einfahrt.jpg');
    fs.mkdirSync(path.dirname(out), { recursive: true });
    await app.evaluate((_e, f) => { globalThis.__gcE2E.saveDialogPaths.push(f); }, out);
    await p.locator('.cm-act').first().click();
    await expect(page.locator('#toasts .toast-success')).toContainText(/Standbild gespeichert|Still saved/);
    const asked = await app.evaluate(() => globalThis.__gcE2E.saveDialogs);
    expect(path.basename(asked.at(-1).defaultPath)).toMatch(/^Einfahrt \d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}\.jpg$/);
    const saved = fs.readFileSync(out);
    expect(saved.subarray(0, 3)).toEqual(Buffer.from([0xff, 0xd8, 0xff]));

    // the live answer ends with its token → a new one is asked for
    const before = door.log.filter((l) => l.route === `cameras/home/${CAM1}/live`).length;
    await expect.poll(() => door.log.filter((l) => l.route === `cameras/home/${CAM1}/live`).length, { timeout: 30000 }).toBeGreaterThan(before);

    // a camera the person no longer sees (rights changed): the list says what is left
    door.cameras = door.cameras.filter((c) => c.id !== CAM1);
    await p.locator('.cm-ib').click();
    await expect(p.locator('.cm-chip')).toHaveCount(1);
    await expect(p.locator('.cm-chip.is-on')).toHaveText('Garten');
  });

  test('a camera push: toast with its picture opens that camera; a Ring push stays in the inbox', async ({ launchApp, mock }) => {
    mock.setPush({ topics: [{ id: 'plugin:gatecontrol-door:kamera', label: 'Tür & Kamera · Personen an der Kamera' }, { id: 'plugin:gatecontrol-door:doorbell', label: 'Tür & Kamera · Klingel' }], items: [] });
    const door = mock.setDoor(doorData());
    const { app, page, clickToast } = await launchApp();
    await setupWithApiKey(page, mock);
    await expect(page.locator('#nav-kameras')).toBeVisible();

    mock.pushNotification({
      topic: 'plugin:gatecontrol-door:doorbell', priority: 'high', title: 'Klingel · Haustür', body: 'Haustür · 14:00',
      data: { route: 'plg-gatecontrol-door', door: { type: 'ding', eventId: 9, cameraId: 4, lockId: 1 } },
    });
    mock.pushNotification({
      topic: 'plugin:gatecontrol-door:kamera', priority: 'high', title: 'Person an der Einfahrt', body: 'Niemand ist zu Hause · 14:02',
      collapse_key: `homecam:${CAM1}`, imageUrl: '/notify-media/abcdef0123456789.jpg',
      data: { route: 'plg-gatecontrol-door', door: { type: 'home_camera_event', cameraId: CAM1, eventId: 'e000000000000001' } },
    });
    await expect.poll(() => app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).join('\n---\n')), { timeout: 20000 }).toContain('Person an der Einfahrt');
    // the toast shows the push's picture (Windows toast XML)
    const isWin = await app.evaluate(() => process.platform === 'win32');
    if (isWin) {
      const text = await app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).find((x) => x.includes('Person an der Einfahrt')));
      expect(text).toMatch(/<image src="[^"]+toast-\d+\.jpg"\/>/);
      const ring = await app.evaluate(() => globalThis.__gcE2E.toasts.map((x) => x.text).find((x) => x.includes('Klingel · Haustür')));
      expect(ring).not.toMatch(/<image src=/);
    }
    expect(door.media).toContain('notify.jpg');

    // toast click → Kameras on that camera
    expect(await clickToast('Person an der Einfahrt')).toBe(true);
    await expect(camPage(page)).toHaveClass(/active/);
    await expect(camPage(page).locator('.cm-chip.is-on')).toHaveText('Einfahrt');
    await expect(camPage(page).locator('.cm-clip.is-focus')).toContainText('Person · 0:24');

    // inbox: the camera entry has "Kamera ansehen", the Ring entry does not
    await page.locator('#nav-inbox').click();
    await page.locator('#inbox-list .inbox-row', { hasText: 'Klingel · Haustür' }).click();
    await expect(page.locator('#inbox-detail')).not.toContainText(/Kamera ansehen|View camera/);
    await page.locator('#inbox-list .inbox-row', { hasText: 'Person an der Einfahrt' }).click();
    await page.locator('#inbox-detail .btn-pri', { hasText: /Kamera ansehen|View camera/ }).click();
    await expect(camPage(page)).toHaveClass(/active/);

    // a click on the Ring toast opens the inbox as before
    await page.locator('.nav[data-page="status"]').click();
    expect(await clickToast('Klingel · Haustür')).toBe(true);
    await expect(page.locator('#page-inbox')).toHaveClass(/active/);
  });
});
