# hls.js (vendored)

| Field | Value |
|---|---|
| Source | npm `hls.js@1.7.4` |
| Integrity | `sha512-3GlxGdPvT2YHvQYOt+yOzT/DEior/qJVNIylHA77kgeoBTdQQqi70GwefNEUmHQeNGyjC8U62+bruqW/Tpm+tg==` (checked against the tarball) |
| Files | `dist/hls.min.js`, `LICENSE` (Apache-2.0, Copyright (c) 2017 Dailymotion; parts derived from videojs-contrib-hls, Copyright (c) 2013-2015 Brightcove) |
| Used by | the player of „Medien“ (`src/renderer/media-player.js`): Jellyfin's converted streams (HLS in fMP4) through `gcmedia:` — Chromium has no HLS of its own |

The trailing `//# sourceMappingURL=…` line was removed (the map is not shipped); nothing else was changed. No CDN:
the page loads the file from the app package.

## Content Security Policy

The page allows scripts only from `'self'` and no `blob:` workers, so the player starts hls.js with
`enableWorker: false` (demuxing on the page's thread — enough for one stream). hls.js loads the playlists and
segments with fetch/XHR from `gcmedia:`, which `connect-src` allows; the media element gets a `blob:` MediaSource
(`media-src` allows `blob:`).
