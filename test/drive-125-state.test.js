'use strict';

// Drive 1.25 'mediaFilter' in the view "Fotos" (renderer/drive-photos-state.js): "Alle · Fotos · Videos", the filter
// only while Drive knows it, a video's length on its tile; the texts in both languages.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const PS = require('../src/renderer/drive-photos-state');
const de = require('../src/i18n/de.json');
const en = require('../src/i18n/en.json');

const t = (k) => k;

describe('Drive 1.25: only pictures or only videos', () => {
  it('the feature, the choices, the filter as sent', () => {
    assert.equal(PS.features({ features: ['photos', 'mediaFilter'] }).media, true);
    assert.equal(PS.features({ features: ['photos'] }).media, false);
    assert.deepEqual(PS.mediaChoices(t).map((c) => [c.key, c.label]), [['', 'drive.photos.media.all'], ['image', 'drive.photos.media.images'], ['video', 'drive.photos.media.videos']]);
    const me = { features: ['mediaFilter'] };
    assert.equal(PS.mediaOf('video', me), 'video');
    assert.equal(PS.mediaOf('image', me), 'image');
    assert.equal(PS.mediaOf('', me), null);
    assert.equal(PS.mediaOf('gif', me), null);
    assert.equal(PS.mediaOf('video', { features: ['photos'] }), null, 'an older Drive: both');
    assert.equal(PS.mediaOf('video', null), null);
  });

  it('a video\'s length', () => {
    assert.equal(PS.durationText(7000), '0:07');
    assert.equal(PS.durationText(83456), '1:23');
    assert.equal(PS.durationText(3723000), '1:02:03');
    assert.equal(PS.durationText(0), '');
    assert.equal(PS.durationText(null), '');
  });

  it('the texts, German and English', () => {
    assert.deepEqual(de.drive.photos.media, { label: 'Fotos oder Videos', all: 'Alle', images: 'Fotos', videos: 'Videos' });
    assert.deepEqual(en.drive.photos.media, { label: 'Photos or videos', all: 'All', images: 'Photos', videos: 'Videos' });
    assert.equal(de.drive.photos.duration, 'Länge {{d}}');
    assert.deepEqual(de.drive.search.media, { label: 'Nur Fotos oder nur Videos', image: 'Fotos', video: 'Videos' });
    assert.deepEqual(Object.keys(en.drive.search.media), Object.keys(de.drive.search.media));
  });
});
