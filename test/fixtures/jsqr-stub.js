'use strict';
// jsQR stand-in: "decodes" whatever the test put into globalThis.__qrPayload.
module.exports = () => (globalThis.__qrPayload == null ? null : { data: globalThis.__qrPayload });
