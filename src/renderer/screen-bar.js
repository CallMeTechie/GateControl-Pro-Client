/* GateControl – Fernzugriff stage 7: the bar at the top while "Bildschirm teilen" runs (screen-bar.html).
   „Lena Vogt steuert deinen Bildschirm · 03:41 · Nur ansehen · Beenden“. Texts come from the main process. */
(function () {
	'use strict';
	var $ = function (id) { return document.getElementById(id); };
	var st = null;
	var timer = null;

	function fill(text, name) { return String(text || '').replace('{{ name }}', name); }
	function two(n) { return n < 10 ? '0' + n : String(n); }

	function tick() {
		if (!st || !st.since) { $('sb-time').textContent = ''; return; }
		var s = Math.max(0, Math.floor((Date.now() - st.since) / 1000));
		var h = Math.floor(s / 3600);
		$('sb-time').textContent = (h ? h + ':' + two(Math.floor(s / 60) % 60) : two(Math.floor(s / 60))) + ':' + two(s % 60);
	}

	function render(s) {
		st = s;
		var x = s.texts || {};
		var name = s.viewer || x.somebody || '';
		var control = s.mode === 'control';
		var text;
		if (s.state === 'connecting') text = x.connecting;
		else if (s.state === 'waiting') text = fill(x.waiting, name);
		else text = fill(control ? x.control : x.view, name);
		if (s.paused) text += ' · ' + (x.paused || '');
		$('sb-text').textContent = text;
		$('sb').className = 'sb' + (control ? ' sb-control' : '');
		$('sb').setAttribute('aria-label', x.label || '');
		$('sb-hand').style.display = control ? '' : 'none';
		$('sb-eye').style.display = control ? 'none' : '';
		$('sb-view-only').hidden = !control;
		$('sb-view-only').textContent = x.viewOnly || '';
		$('sb-stop').textContent = x.stop || '';
		clearInterval(timer);
		timer = setInterval(tick, 1000);
		tick();
	}

	$('sb-stop').addEventListener('click', function () { $('sb-stop').disabled = true; window.gcBar.stop(); });
	$('sb-view-only').addEventListener('click', function () { $('sb-view-only').hidden = true; window.gcBar.viewOnly(); });
	window.gcBar.onState(function (s) { $('sb-stop').disabled = false; render(s); });
})();
