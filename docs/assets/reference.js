/* =========================================================
   reference.js — リファレンス系ドキュメント（09, 10, …）共有スクリプト
   マークアップ規約（HTML 側に書くだけで動く）:
     ・表示フィルタ:  <button class="ctl" data-toggle="body に付ける class">ラベル</button>
         ON にすると body へ class を付け、全ノードを展開し、
         ボタン文言を data-restore-label（既定「すべて表示に戻す」）へ替える
     ・全展開/全折りたたみ: <button class="ctl" data-action="expand|collapse">
         collapse はルート（details.d0）を残して閉じる
   ========================================================= */
(function () {
  'use strict';
  var body = document.body;

  function openAll() {
    document.querySelectorAll('details.node').forEach(function (d) { d.open = true; });
  }

  document.querySelectorAll('button.ctl[data-toggle]').forEach(function (btn) {
    var cls = btn.dataset.toggle;
    var offLabel = btn.textContent;
    var onLabel = btn.dataset.restoreLabel || 'すべて表示に戻す';
    btn.setAttribute('aria-pressed', 'false');
    btn.addEventListener('click', function () {
      var on = body.classList.toggle(cls);
      btn.classList.toggle('active', on);
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.textContent = on ? onLabel : offLabel;
      if (on) { openAll(); }
    });
  });

  document.querySelectorAll('button.ctl[data-action="expand"]').forEach(function (btn) {
    btn.addEventListener('click', openAll);
  });

  document.querySelectorAll('button.ctl[data-action="collapse"]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('details.node').forEach(function (d) {
        if (!d.classList.contains('d0')) { d.open = false; }
      });
    });
  });
})();
